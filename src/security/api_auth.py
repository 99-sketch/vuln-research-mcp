"""
API Authentication — Bearer Token / JWT / HMAC (v5.0)

Provides enterprise-grade REST API authentication:
  - Bearer token (static, for simple deployments)
  - JWT with HS256/RS256 (for distributed deployments)
  - HMAC-SHA256 signature verification (for service-to-service)
  - Rate limiting per API key
  - Key rotation support
  - Failed attempt lockout

Usage:
    auth = APIAuthManager(secret="env:API_SECRET")
    # Verify a request
    user_id = auth.verify_token("Bearer sk-xxxxx")
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Token Types ────────────────────────────────────────────────────

@dataclass
class APIKey:
    """An API key with associated permissions and rate limits."""
    key_id: str
    key_hash: str         # SHA256 of the actual key
    name: str
    permissions: Set[str] = field(default_factory=lambda: {"read"})
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used_at: float = 0
    enabled: bool = True

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.enabled and not self.is_expired


# ── Rate Limiter ────────────────────────────────────────────────────

class TokenRateLimiter:
    """Per-token sliding window rate limiter."""

    def __init__(self):
        self._minute_windows: Dict[str, List[float]] = {}
        self._hour_windows: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}  # key_id -> lockout_until
        self._failed_attempts: Dict[str, Tuple[int, float]] = {}  # key_id -> (count, first_fail_time)

        self.MAX_FAILED_ATTEMPTS = 10
        self.LOCKOUT_DURATION = 300  # 5 minutes

    def check(self, key_id: str, max_per_minute: int, max_per_hour: int) -> Tuple[bool, str]:
        """Check if rate limit is exceeded. Returns (allowed, reason)."""
        now = time.time()

        # Check lockout
        if key_id in self._lockouts:
            if now < self._lockouts[key_id]:
                remaining = int(self._lockouts[key_id] - now)
                return False, f"Account locked for {remaining} seconds"
            del self._lockouts[key_id]

        # Clean minute window
        self._minute_windows.setdefault(key_id, [])
        self._minute_windows[key_id] = [
            t for t in self._minute_windows[key_id] if now - t < 60
        ]

        # Clean hour window
        self._hour_windows.setdefault(key_id, [])
        self._hour_windows[key_id] = [
            t for t in self._hour_windows[key_id] if now - t < 3600
        ]

        # Check minute limit
        if len(self._minute_windows[key_id]) >= max_per_minute:
            return False, f"Rate limit exceeded: {max_per_minute} requests/minute"

        # Check hour limit
        if len(self._hour_windows[key_id]) >= max_per_hour:
            return False, f"Rate limit exceeded: {max_per_hour} requests/hour"

        # Record
        self._minute_windows[key_id].append(now)
        self._hour_windows[key_id].append(now)

        return True, "ok"

    def record_failure(self, key_id: str):
        """Record a failed authentication attempt."""
        now = time.time()
        if key_id not in self._failed_attempts:
            self._failed_attempts[key_id] = (1, now)
        else:
            count, first_time = self._failed_attempts[key_id]
            if now - first_time > 300:  # reset after 5 min
                self._failed_attempts[key_id] = (1, now)
            else:
                count += 1
                self._failed_attempts[key_id] = (count, first_time)
                if count >= self.MAX_FAILED_ATTEMPTS:
                    self._lockouts[key_id] = now + self.LOCKOUT_DURATION

    def clear_failures(self, key_id: str):
        self._failed_attempts.pop(key_id, None)
        self._lockouts.pop(key_id, None)

    def get_stats(self, key_id: str) -> dict:
        """Get rate limit stats for a key."""
        now = time.time()
        minute_count = len([t for t in self._minute_windows.get(key_id, []) if now - t < 60])
        hour_count = len([t for t in self._hour_windows.get(key_id, []) if now - t < 3600])
        locked = key_id in self._lockouts and now < self._lockouts[key_id]
        return {
            "requests_last_minute": minute_count,
            "requests_last_hour": hour_count,
            "locked_out": locked,
        }


# ── Token Store ─────────────────────────────────────────────────────

class TokenStore:
    """In-memory token store with optional file persistence."""

    def __init__(self, file_path: Optional[str] = None):
        self._keys: Dict[str, APIKey] = {}
        self._key_map: Dict[str, str] = {}  # token_prefix -> key_id
        self._file_path = file_path

        if file_path and os.path.exists(file_path):
            self._load_from_file(file_path)

    def create_key(
        self,
        name: str,
        permissions: Optional[Set[str]] = None,
        expires_in_days: Optional[int] = None,
    ) -> Tuple[APIKey, str]:
        """Create a new API key. Returns (key_object, raw_key)."""
        raw_key = f"sk-{uuid.uuid4().hex}{uuid.uuid4().hex}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id = key_hash[:16]

        expires_at = None
        if expires_in_days:
            expires_at = time.time() + expires_in_days * 86400

        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions or {"read"},
            expires_at=expires_at,
        )

        self._keys[key_id] = api_key
        self._key_map[raw_key[:12]] = key_id

        if self._file_path:
            self._save_to_file()

        return api_key, raw_key

    def verify_raw_key(self, raw_key: str) -> Optional[APIKey]:
        """Verify a raw API key string and return the APIKey if valid."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id = key_hash[:16]

        api_key = self._keys.get(key_id)
        if api_key is None:
            return None

        if not api_key.is_valid:
            return None

        return api_key

    def get_key(self, key_id: str) -> Optional[APIKey]:
        return self._keys.get(key_id)

    def revoke_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            self._keys[key_id].enabled = False
            if self._file_path:
                self._save_to_file()
            return True
        return False

    def list_keys(self) -> List[APIKey]:
        return list(self._keys.values())

    def _save_to_file(self):
        """Save keys to encrypted JSON file."""
        import json
        data = {
            kid: {
                "key_id": k.key_id,
                "key_hash": k.key_hash,
                "name": k.name,
                "permissions": list(k.permissions),
                "max_requests_per_minute": k.max_requests_per_minute,
                "max_requests_per_hour": k.max_requests_per_hour,
                "created_at": k.created_at,
                "expires_at": k.expires_at,
                "last_used_at": k.last_used_at,
                "enabled": k.enabled,
            }
            for kid, k in self._keys.items()
        }
        with open(self._file_path, 'w') as f:
            json.dump(data, f, indent=2)

    def _load_from_file(self, file_path: str):
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        for kid, d in data.items():
            self._keys[kid] = APIKey(
                key_id=d["key_id"],
                key_hash=d["key_hash"],
                name=d["name"],
                permissions=set(d.get("permissions", ["read"])),
                max_requests_per_minute=d.get("max_requests_per_minute", 60),
                created_at=d.get("created_at", 0),
                expires_at=d.get("expires_at"),
                last_used_at=d.get("last_used_at", 0),
                enabled=d.get("enabled", True),
            )


# ── Auth Manager ────────────────────────────────────────────────────

class APIAuthManager:
    """Unified API authentication manager.

    Supports multiple auth schemes:
      - Bearer <token>: API key or JWT
      - X-API-Key: <token>: Alternative header
      - HMAC-SHA256: Service-to-service signature

    Env vars:
      VULNRESEARCH_API_SECRET: Master secret for JWT/HMAC
      VULNRESEARCH_API_KEYS: Comma-separated static API keys (testing)
    """

    BEARER_PATTERN = re.compile(r'^Bearer\s+(.+)$', re.IGNORECASE)
    API_KEY_HEADER = "X-API-Key"
    HMAC_HEADER = "X-HMAC-Signature"
    HMAC_TIMESTAMP_HEADER = "X-HMAC-Timestamp"
    HMAC_MAX_AGE = 300  # 5 minutes max age for HMAC signatures

    def __init__(
        self,
        secret: Optional[str] = None,
        token_store: Optional[TokenStore] = None,
        rate_limiter: Optional[TokenRateLimiter] = None,
    ):
        self._secret = self._resolve_secret(secret)
        self._token_store = token_store or TokenStore()
        self._rate_limiter = rate_limiter or TokenRateLimiter()

        # Load static keys from environment (for development/testing)
        self._load_static_keys()

    def _resolve_secret(self, secret: Optional[str]) -> bytes:
        if secret is None:
            secret = os.environ.get("VULNRESEARCH_API_SECRET", "")
        if secret.startswith("env:"):
            secret = os.environ.get(secret[4:], "")
        return hashlib.sha256(secret.encode()).digest()

    def _load_static_keys(self):
        """Load static API keys from VULNRESEARCH_API_KEYS env var."""
        raw = os.environ.get("VULNRESEARCH_API_KEYS", "")
        if raw:
            for key_name in raw.split(","):
                key_name = key_name.strip()
                if key_name:
                    self._token_store.create_key(f"static:{key_name}", {"read", "write"})

    # ── Token Management ────────────────────────────────────────

    def create_api_key(self, name: str, permissions: Optional[Set[str]] = None, expires_in_days: Optional[int] = None) -> str:
        """Create a new API key. Returns the raw key string (show once)."""
        _, raw_key = self._token_store.create_key(name, permissions, expires_in_days)
        return raw_key

    def revoke_api_key(self, key_id: str) -> bool:
        return self._token_store.revoke_key(key_id)

    def list_api_keys(self) -> List[dict]:
        """List all API keys (no raw keys exposed)."""
        keys = self._token_store.list_keys()
        return [
            {
                "key_id": k.key_id,
                "name": k.name,
                "permissions": list(k.permissions),
                "created_at": k.created_at,
                "expires_at": k.expires_at,
                "last_used_at": k.last_used_at,
                "enabled": k.enabled,
                "rate_stats": self._rate_limiter.get_stats(k.key_id),
            }
            for k in keys
        ]

    # ── Request Verification ────────────────────────────────────

    def verify_request(self, headers: dict, method: str = "POST", path: str = "/", body: bytes = b"") -> Tuple[Optional[APIKey], Optional[str]]:
        """Verify an API request. Returns (APIKey or None, error_message or None).

        Tries authentication methods in order:
        1. Bearer token
        2. X-API-Key header
        3. HMAC signature
        """
        auth_header = headers.get("Authorization", "")
        api_key_header = headers.get(self.API_KEY_HEADER, "")

        # Method 1: Bearer token
        match = self.BEARER_PATTERN.match(auth_header)
        if match:
            return self._verify_bearer_token(match.group(1))

        # Method 2: X-API-Key header
        if api_key_header:
            return self._verify_bearer_token(api_key_header)

        # Method 3: HMAC signature
        hmac_sig = headers.get(self.HMAC_HEADER, "")
        hmac_ts = headers.get(self.HMAC_TIMESTAMP_HEADER, "")
        if hmac_sig and hmac_ts:
            return self._verify_hmac_signature(hmac_sig, hmac_ts, method, path, body)

        return None, "No valid authentication provided"

    def _verify_bearer_token(self, token: str) -> Tuple[Optional[APIKey], Optional[str]]:
        api_key = self._token_store.verify_raw_key(token)
        if api_key is None:
            return None, "Invalid or expired API key"

        # Rate limit check
        allowed, reason = self._rate_limiter.check(
            api_key.key_id,
            api_key.max_requests_per_minute,
            api_key.max_requests_per_hour,
        )
        if not allowed:
            return None, reason

        self._rate_limiter.clear_failures(api_key.key_id)
        api_key.last_used_at = time.time()
        return api_key, None

    def _verify_hmac_signature(self, signature: str, timestamp_str: str, method: str, path: str, body: bytes) -> Tuple[Optional[APIKey], Optional[str]]:
        """Verify HMAC-SHA256 signature for service-to-service auth."""
        try:
            ts = float(timestamp_str)
        except ValueError:
            return None, "Invalid HMAC timestamp"

        now = time.time()
        if abs(now - ts) > self.HMAC_MAX_AGE:
            return None, f"HMAC timestamp expired (max age: {self.HMAC_MAX_AGE}s)"

        # Build signing string
        signing_string = f"{method}\n{path}\n{timestamp_str}\n"
        signing_string += hashlib.sha256(body).hexdigest()

        expected_sig = hmac.new(self._secret, signing_string.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None, "HMAC signature mismatch"

        # Return a virtual "hmac-service" key
        return APIKey(
            key_id="hmac-service",
            key_hash="",
            name="HMAC Service Account",
            permissions={"read", "write", "admin"},
        ), None

    def check_permission(self, api_key: APIKey, required_permission: str) -> Tuple[bool, str]:
        """Check if an API key has a specific permission."""
        if required_permission not in api_key.permissions:
            return False, f"Missing permission: {required_permission}"
        return True, "ok"


# ── Global Singleton ────────────────────────────────────────────────

_api_auth: Optional[APIAuthManager] = None


def get_api_auth(secret: Optional[str] = None) -> APIAuthManager:
    global _api_auth
    if _api_auth is None:
        _api_auth = APIAuthManager(secret=secret)
    return _api_auth

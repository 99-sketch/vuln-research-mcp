"""
External Data Context Sanitizer (v5.0)

Prevents indirect prompt injection by sanitizing external data
before it enters LLM context. All CVE descriptions, exploit
details, NVD API responses, and third-party data are cleaned.

Defense layers:
  1. Strip hidden Unicode control characters (RLO, LRO, ZWJ, etc.)
  2. Remove markdown/image links that could inject instructions
  3. Detect and strip "system prompt" / "ignore previous" patterns
  4. Truncate excessively long inputs (anti-DoS)
  5. Detect embedded code blocks with suspicious content
  6. Clean HTML/XML tags that could carry XSS/prompt payloads
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


# ── Unicode Dangerous Characters ───────────────────────────────────

# Characters commonly used in prompt injection attacks
DANGEROUS_UNICODE = {
    '\u202a',  # LEFT-TO-RIGHT EMBEDDING (LRE)
    '\u202b',  # RIGHT-TO-LEFT EMBEDDING (RLE)
    '\u202c',  # POP DIRECTIONAL FORMATTING
    '\u202d',  # LEFT-TO-RIGHT OVERRIDE (LRO)
    '\u202e',  # RIGHT-TO-LEFT OVERRIDE (RLO)
    '\u2060',  # WORD JOINER (used to hide text)
    '\u2061',  # FUNCTION APPLICATION
    '\u2062',  # INVISIBLE TIMES
    '\u2063',  # INVISIBLE SEPARATOR
    '\u2064',  # INVISIBLE PLUS
    '\u200b',  # ZERO WIDTH SPACE (ZWSP)
    '\u200c',  # ZERO WIDTH NON-JOINER (ZWNJ)
    '\u200d',  # ZERO WIDTH JOINER (ZWJ)
    '\u200e',  # LEFT-TO-RIGHT MARK (LRM)
    '\u200f',  # RIGHT-TO-LEFT MARK (RLM)
    '\ufeff',  # ZERO WIDTH NO-BREAK SPACE (BOM/ZWNBSP)
    '\u00ad',  # SOFT HYPHEN (invisible)
    '\u180e',  # MONGOLIAN VOWEL SEPARATOR
    '\u034f',  # COMBINING GRAPHEME JOINER
}

# Homoglyph characters commonly used to bypass filters
# e.g., Greek "ο" (omicron) looks like Latin "o"
HOMOGLYPH_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0445': 'x',  # Cyrillic х
    '\u0455': 's',  # Cyrillic ѕ
    '\u0456': 'i',  # Cyrillic і
    '\u03bf': 'o',  # Greek ο (omicron)
    '\u03bd': 'v',  # Greek ν (nu)
    '\u0391': 'A',  # Greek Α
    '\u0392': 'B',  # Greek Β
    '\u0395': 'E',  # Greek Ε
    '\u0397': 'H',  # Greek Η
    '\u0399': 'I',  # Greek Ι
    '\u039a': 'K',  # Greek Κ
    '\u039c': 'M',  # Greek Μ
    '\u039d': 'N',  # Greek Ν
    '\u039f': 'O',  # Greek Ο
    '\u03a1': 'P',  # Greek Ρ
    '\u03a4': 'T',  # Greek Τ
    '\u03a5': 'Y',  # Greek Υ
    '\u03a7': 'X',  # Greek Χ
    '\u0396': 'Z',  # Greek Ζ
}


# ── Prompt Injection Patterns ──────────────────────────────────────

# Patterns that indicate potential prompt injection in external data
PROMPT_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|directives?|prompts?|rules?)', re.IGNORECASE),
     "Instruction override pattern: 'ignore previous instructions'"),
    (re.compile(r'(?:you\s+(?:are|must|should|will|shall|need\s+to|have\s+to))\s+(?:now\s+)?(?:act\s+as|behave\s+as|roleplay|pretend|impersonate)', re.IGNORECASE),
     "Role coercion pattern: 'you must act as'"),
    (re.compile(r'(?:new\s+(?:system\s+)?prompt|system\s+message|override\s+prompt|prompt\s+injection)', re.IGNORECASE),
     "Explicit prompt manipulation reference"),
    (re.compile(r'(?:from\s+now\s+on|starting\s+now|hereafter)\s*,?\s*(?:you\s+)?(?:(?:must|will|should)\s+)?(?:reply|respond|output|print|say)', re.IGNORECASE),
     "Behavior reset pattern: 'from now on, you will reply'"),
    re.compile(r'<\|im_start\|>|<\|im_end\|>|<\|\s*(?:system|user|assistant)\s*\|>', re.IGNORECASE),
    (re.compile(r'<\|\s*endofprompt\s*\|>', re.IGNORECASE),
     "Boundary injection: '<|endofprompt|>' style tokens"),
    (re.compile(r'(?:```|~~~)(?:system|instructions?|rules?)\s*\n', re.IGNORECASE),
     "Code-fenced system instructions"),
    (re.compile(r'DO\s+NOT\s+(?:OUTPUT|PRINT|DISPLAY|SHOW|RESPOND|REPLY)', re.IGNORECASE),
     "Output suppression attack"),
    (re.compile(r'(?:\[INST\]|\[SYSTEM\]|\[/INST\]|\[/SYSTEM\]|<<SYS>>|<</SYS>>)', re.IGNORECASE),
     "LLM-specific control tokens"),
    (re.compile(r'(?:输出|回复|回答|打印|显示)\s*(?:以下|下列|如下)\s*(?:内容|文本|文字)', re.IGNORECASE),
     "Chinese instruction injection: '输出以下内容'"),
    (re.compile(r'!!\s*(?:system|instruction|override|prompt)', re.IGNORECASE),
     "Bangs-based system override"),
]

# HTML/XML patterns that could carry payloads
HTML_SCRIPT_PATTERN = re.compile(
    r'<script[^>]*>.*?</script>|<iframe[^>]*>.*?</iframe>|<style[^>]*>.*?</style>',
    re.IGNORECASE | re.DOTALL,
)
HTML_EVENT_PATTERN = re.compile(
    r'\bon\w+\s*=\s*["\'][^"\']*["\']',  # onclick, onerror, etc.
    re.IGNORECASE,
)
HTML_ENTITY_PATTERN = re.compile(r'&#x?[0-9a-f]+;', re.IGNORECASE)
DATA_URI_PATTERN = re.compile(r'data:text/html[^"\']*', re.IGNORECASE)


# ── Sanitization Result ────────────────────────────────────────────

@dataclass
class SanitizationReport:
    """Report of what was cleaned from the input."""
    original_length: int
    sanitized_length: int
    flags: List[str] = field(default_factory=list)
    truncated: bool = False
    blocked: bool = False

    @property
    def was_modified(self) -> bool:
        return self.original_length != self.sanitized_length or len(self.flags) > 0 or self.blocked


# ── Main Sanitizer ──────────────────────────────────────────────────

class DataContextSanitizer:
    """Sanitize external data before it enters LLM context.

    All incoming data from NVD, CISA, GitHub, Exploit-DB, third-party
    APIs must pass through this sanitizer before being returned to
    the LLM as tool output.

    Usage:
        sanitizer = DataContextSanitizer()
        cleaned_text, report = sanitizer.sanitize(raw_cve_description)
        if report.blocked:
            return "[BLOCKED] Unsafe content detected in external data"
        return cleaned_text
    """

    MAX_LENGTH = 32768  # 32KB per field (prevents DoS via huge inputs)
    MAX_FIELDS = 500    # max fields in structured data

    def __init__(
        self,
        strip_dangerous_unicode: bool = True,
        normalize_homoglyphs: bool = True,
        detect_prompt_injection: bool = True,
        clean_html: bool = True,
        truncate_long_inputs: bool = True,
        aggressive_mode: bool = False,
    ):
        self.strip_dangerous_unicode = strip_dangerous_unicode
        self.normalize_homoglyphs = normalize_homoglyphs
        self.detect_prompt_injection = detect_prompt_injection
        self.clean_html = clean_html
        self.truncate_long_inputs = truncate_long_inputs
        self.aggressive_mode = aggressive_mode

    def sanitize(self, text: str, source: str = "unknown") -> Tuple[str, SanitizationReport]:
        """Sanitize a single text string from external source.

        Args:
            text: Raw input text from external API/file
            source: Source identifier for logging (e.g. "NVD", "Exploit-DB")

        Returns:
            (cleaned_text, report)
        """
        report = SanitizationReport(original_length=len(text))

        if not text:
            return text, report

        cleaned = text

        # Layer 1: Strip dangerous Unicode
        if self.strip_dangerous_unicode:
            cleaned, unicode_flags = self._strip_dangerous_unicode(cleaned)
            report.flags.extend(unicode_flags)

        # Layer 2: Normalize homoglyphs
        if self.normalize_homoglyphs:
            cleaned, homo_flags = self._normalize_homoglyphs(cleaned)
            report.flags.extend(homo_flags)

        # Layer 3: Detect prompt injection patterns
        if self.detect_prompt_injection:
            cleaned, inject_flags, blocked = self._check_prompt_injection(cleaned)
            report.flags.extend(inject_flags)
            if blocked:
                report.blocked = True
                report.sanitized_length = 0
                return "", report

        # Layer 4: Clean HTML/XML payloads
        if self.clean_html:
            cleaned, html_flags = self._clean_html(cleaned)
            report.flags.extend(html_flags)

        # Layer 5: Truncate long inputs
        if self.truncate_long_inputs and len(cleaned) > self.MAX_LENGTH:
            cleaned = cleaned[:self.MAX_LENGTH] + f"\n\n[... truncated from {len(text)} to {self.MAX_LENGTH} chars by DataContextSanitizer]"
            report.truncated = True
            report.flags.append(f"truncated:{len(text)}->{self.MAX_LENGTH}")

        report.sanitized_length = len(cleaned)
        return cleaned, report

    def sanitize_structured(
        self, data: dict, source: str = "unknown", depth: int = 0
    ) -> Tuple[dict, SanitizationReport]:
        """Recursively sanitize a dictionary of structured data.

        Limits recursion depth and field count to prevent DoS.
        """
        if depth > 20:
            return {"[MAX_DEPTH]": "recursion limit"}, SanitizationReport(
                original_length=0, sanitized_length=0, flags=["recursion_depth_exceeded"]
            )

        combined_report = SanitizationReport(original_length=0, sanitized_length=0)
        cleaned = {}

        for i, (key, value) in enumerate(data.items()):
            if i >= self.MAX_FIELDS:
                combined_report.flags.append(f"field_count_truncated:{len(data)}")
                break

            # Sanitize key
            clean_key, key_report = self.sanitize(str(key), source)
            combined_report.flags.extend(key_report.flags)
            if key_report.blocked:
                clean_key = "[BLOCKED_KEY]"

            # Sanitize value
            if isinstance(value, str):
                clean_value, val_report = self.sanitize(value, source)
                combined_report.flags.extend(val_report.flags)
                cleaned[clean_key] = clean_value
            elif isinstance(value, dict):
                clean_value, val_report = self.sanitize_structured(value, source, depth + 1)
                combined_report.flags.extend(val_report.flags)
                cleaned[clean_key] = clean_value
            elif isinstance(value, list):
                clean_list = []
                for item in value[:self.MAX_FIELDS]:
                    if isinstance(item, str):
                        ci, r = self.sanitize(item, source)
                        clean_list.append(ci)
                    elif isinstance(item, dict):
                        ci, r = self.sanitize_structured(item, source, depth + 1)
                        clean_list.append(ci)
                    else:
                        clean_list.append(item)
                cleaned[clean_key] = clean_list
            else:
                cleaned[clean_key] = value

        return cleaned, combined_report

    # ── Private Helpers ───────────────────────────────────────────

    def _strip_dangerous_unicode(self, text: str) -> Tuple[str, List[str]]:
        flags = []
        chars = []
        modified = False

        for ch in text:
            if ch in DANGEROUS_UNICODE:
                modified = True
                name = unicodedata.name(ch, "UNKNOWN")
                flags.append(f"unicode_stripped:U+{ord(ch):04X}({name})")
            else:
                chars.append(ch)

        if modified:
            return ''.join(chars), flags
        return text, []

    def _normalize_homoglyphs(self, text: str) -> Tuple[str, List[str]]:
        flags = []
        chars = []
        modified = False

        for ch in text:
            if ch in HOMOGLYPH_MAP:
                modified = True
                flags.append(f"homoglyph_normalized:U+{ord(ch):04X}->{HOMOGLYPH_MAP[ch]}")
                chars.append(HOMOGLYPH_MAP[ch])
            else:
                chars.append(ch)

        if modified:
            return ''.join(chars), flags
        return text, []

    def _check_prompt_injection(self, text: str) -> Tuple[str, List[str], bool]:
        """Check for prompt injection patterns. In aggressive mode,
        block the content entirely if found. Otherwise, flag and sanitize."""
        flags = []
        cleaned = text

        for pattern, description in PROMPT_INJECTION_PATTERNS:
            if pattern.search(cleaned):
                flags.append(f"injection_detected:{description}")
                if self.aggressive_mode:
                    return cleaned, flags, True  # block entirely
                # In non-aggressive mode, replace patterns with sanitized text
                cleaned = pattern.sub(f"[INJECTION_BLOCKED:{description[:30]}]", cleaned)

        return cleaned, flags, False

    def _clean_html(self, text: str) -> Tuple[str, List[str]]:
        """Remove dangerous HTML elements and event handlers."""
        flags = []

        if HTML_SCRIPT_PATTERN.search(text):
            flags.append("html_script_removed")
            text = HTML_SCRIPT_PATTERN.sub("[HTML_SCRIPT_REMOVED]", text)

        if HTML_EVENT_PATTERN.search(text):
            flags.append("html_event_handler_removed")
            text = HTML_EVENT_PATTERN.sub("[EVENT_REMOVED]", text)

        if DATA_URI_PATTERN.search(text):
            flags.append("data_uri_removed")
            text = DATA_URI_PATTERN.sub("[DATA_URI_REMOVED]", text)

        # Decode HTML entities to prevent encoding-based injection
        decoded_count = 0
        while True:
            decoded = html.unescape(text)
            if decoded == text:
                break
            text = decoded
            decoded_count += 1
            if decoded_count > 5:  # prevent infinite loops
                break

        return text, flags


# ── Global Singleton ────────────────────────────────────────────────

_data_sanitizer: Optional[DataContextSanitizer] = None


def get_data_sanitizer(aggressive: bool = False) -> DataContextSanitizer:
    """Get or create the global DataContextSanitizer instance."""
    global _data_sanitizer
    if _data_sanitizer is None:
        _data_sanitizer = DataContextSanitizer(aggressive_mode=aggressive)
    return _data_sanitizer

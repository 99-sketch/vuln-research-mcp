"""REST API server — wraps the gateway for standalone HTTP access."""
from __future__ import annotations

import uvicorn
from src.gateway.rest_api import RestAPIGateway


def main():
    gateway = RestAPIGateway()
    app = gateway.app
    if app is None:
        raise RuntimeError("FastAPI not installed")
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="info")


if __name__ == "__main__":
    main()

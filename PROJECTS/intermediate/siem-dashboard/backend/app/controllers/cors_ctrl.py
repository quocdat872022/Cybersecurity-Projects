"""
©AngelaMos | 2026
cors_ctrl.py

Business logic for CORS misconfiguration scanning

Thin coordinator between the /v1/cors-scan route and the CORSScanner
engine. Validates the target URL is reachable before launching a full
scan, and wraps the result for serialization.

Key exports:
  run_cors_scan - reads g.validated, runs CORSScanner, returns dict

Connects to:
  engine/cors_scanner.py - CORSScanner, CORSScanResult
  routes/cors.py        - called from route handler
  schemas/cors.py       - CORSScanRequest validated onto g.validated
"""

from typing import Any

from flask import g

from app.engine.cors_scanner import CORSScanner


def run_cors_scan() -> dict[str, Any]:
    """
    Launch a CORS misconfiguration scan against the requested target.
    Reads g.validated (CORSScanRequest) and returns a serialisable dict.
    """
    data = g.validated

    extra: list[str] = data.extra_endpoints or []

    scanner = CORSScanner(
        target_url=data.target_url,
        extra_endpoints=extra if extra else None,
        timeout=data.timeout_seconds,
    )

    result = scanner.scan()
    return result.to_dict()
"""
©AngelaMos | 2026
cors.py  (routes)

Route handler for the CORS scanner API (/v1/cors-scan)

Mounts POST /v1/cors-scan – runs a CORS misconfiguration scan against
a caller-supplied target URL and returns structured findings.

Connects to:
  controllers/cors_ctrl.py - run_cors_scan()
  schemas/cors.py          - CORSScanRequest
  core/decorators          - endpoint, S, R
  routes/__init__.py       - cors_bp registered here
"""

from typing import Any

from flask import Blueprint

from app.controllers import cors_ctrl
from app.core.decorators import endpoint, S, R
from app.schemas.cors import CORSScanRequest


cors_bp = Blueprint("cors", __name__)


@cors_bp.post("")
@endpoint()
@S(CORSScanRequest)
@R()
def scan_cors() -> Any:
    """
    Run a CORS misconfiguration scan against the supplied target URL.

    Requires authentication. The scan is performed server-side so the
    browser's same-origin policy does not interfere with the results.

    Request body (JSON):
      target_url       string  required  Base URL to scan
      extra_endpoints  array   optional  Additional paths to probe
      timeout_seconds  int     optional  Per-request timeout (1-30, default 10)

    Returns a CORSScanResult dict with fields:
      vulnerable       bool
      highest_severity string
      finding_count    int
      findings         array of CORSFinding dicts
      endpoints_tested array
      scan_duration_ms int
    """
    return cors_ctrl.run_cors_scan()
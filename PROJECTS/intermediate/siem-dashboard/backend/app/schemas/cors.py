"""
©AngelaMos | 2026
cors.py  (schemas)

Pydantic schema for the CORS scan request.

Key exports:
  CORSScanRequest - validated body for POST /v1/cors-scan

Connects to:
  routes/cors.py      - passed to S()
  controllers/cors_ctrl.py - read from g.validated
"""

from pydantic import AnyHttpUrl, BaseModel, Field


class CORSScanRequest(BaseModel):
    """
    Payload for a CORS misconfiguration scan.
    """
    target_url: str = Field(
        min_length=1,
        description="Base URL to scan, e.g. https://api.example.com",
    )
    extra_endpoints: list[str] | None = Field(
        default=None,
        description="Additional URL paths to probe beyond the defaults",
    )
    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=30,
        description="Per-request timeout in seconds (1–30)",
    )
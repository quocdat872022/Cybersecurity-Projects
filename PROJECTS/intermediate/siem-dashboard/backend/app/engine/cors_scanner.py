"""
©AngelaMos | 2026
cors_scanner.py

CORS Misconfiguration Scanner

Tests API endpoints for overly permissive Cross-Origin Resource Sharing
policies. Detects wildcard origins, reflected origins, and the dangerous
combination of credentials + wildcard. Each finding is recorded as a
CORSFinding dataclass and returned as a structured CORSScanResult.

Key exports:
  CORSScanner - main scanner class with .scan() entry point
  CORSScanResult - structured result with findings and severity
  CORSFinding - individual misconfiguration record
  CORSSeverity - severity enum for findings

Connects to:
  controllers/cors_ctrl.py - calls CORSScanner.scan()
  routes/cors.py - exposes /v1/cors-scan endpoint
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import requests
from requests import Response


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 10  # seconds
DEFAULT_ENDPOINTS = ["/", "/api", "/api/v1", "/health"]

ORIGINS_TO_TEST = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://evil.com.target.com",  # suffix-match bypass attempt
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class CORSSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class CORSFinding:
    """A single CORS misconfiguration detected on one endpoint."""
    endpoint: str
    origin_sent: str
    allow_origin: str | None
    allow_credentials: str | None
    allow_methods: str | None
    allow_headers: str | None
    severity: CORSSeverity
    title: str
    description: str
    recommendation: str


@dataclass
class CORSScanResult:
    """Aggregated result for a full CORS scan against a target."""
    target_url: str
    endpoints_tested: list[str]
    findings: list[CORSFinding]
    scan_duration_ms: int
    error: str | None = None

    @property
    def vulnerable(self) -> bool:
        return any(
            f.severity in (
                CORSSeverity.CRITICAL,
                CORSSeverity.HIGH,
                CORSSeverity.MEDIUM,
            )
            for f in self.findings
        )

    @property
    def highest_severity(self) -> str:
        order = [
            CORSSeverity.CRITICAL,
            CORSSeverity.HIGH,
            CORSSeverity.MEDIUM,
            CORSSeverity.LOW,
            CORSSeverity.INFO,
        ]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev.value
        return "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "endpoints_tested": self.endpoints_tested,
            "vulnerable": self.vulnerable,
            "highest_severity": self.highest_severity,
            "finding_count": len(self.findings),
            "findings": [
                {
                    "endpoint": f.endpoint,
                    "origin_sent": f.origin_sent,
                    "allow_origin": f.allow_origin,
                    "allow_credentials": f.allow_credentials,
                    "allow_methods": f.allow_methods,
                    "allow_headers": f.allow_headers,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "scan_duration_ms": self.scan_duration_ms,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class CORSScanner:
    """
    Tests a target URL for CORS misconfiguration across multiple
    endpoints and origin header values.

    Usage:
        scanner = CORSScanner("https://api.example.com")
        result = scanner.scan()
        print(result.vulnerable, result.findings)
    """

    def __init__(
        self,
        target_url: str,
        extra_endpoints: list[str] | None = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.endpoints = list(dict.fromkeys(
            DEFAULT_ENDPOINTS + (extra_endpoints or [])
        ))
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "SIEM-CORS-Scanner/1.0"})

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def scan(self) -> CORSScanResult:
        """
        Run the full CORS scan and return a structured result.
        """
        start = time.monotonic()
        findings: list[CORSFinding] = []
        tested: list[str] = []
        error: str | None = None

        try:
            for path in self.endpoints:
                full_url = f"{self.target_url}{path}"
                tested.append(full_url)
                findings.extend(self._test_endpoint(full_url))
        except Exception as exc:  # pragma: no cover
            error = str(exc)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # De-duplicate identical findings (same endpoint + origin + title)
        seen: set[tuple[str, str, str]] = set()
        unique: list[CORSFinding] = []
        for f in findings:
            key = (f.endpoint, f.origin_sent, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return CORSScanResult(
            target_url=self.target_url,
            endpoints_tested=tested,
            findings=unique,
            scan_duration_ms=elapsed_ms,
            error=error,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _test_endpoint(self, url: str) -> list[CORSFinding]:
        """Test one endpoint against every origin in ORIGINS_TO_TEST."""
        findings: list[CORSFinding] = []

        for origin in ORIGINS_TO_TEST:
            finding = self._probe(url, origin, method="GET")
            if finding:
                findings.append(finding)

        # Additional preflight check (OPTIONS)
        finding = self._probe(url, "https://evil.com", method="OPTIONS")
        if finding:
            findings.append(finding)

        return findings

    def _probe(
        self,
        url: str,
        origin: str,
        method: str = "GET",
    ) -> CORSFinding | None:
        """
        Send one request with an Origin header and analyse the response
        headers for CORS misconfiguration. Returns a CORSFinding or None.
        """
        headers: dict[str, str] = {"Origin": origin}
        if method == "OPTIONS":
            headers.update({
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            })

        try:
            response: Response = self._session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=True,
            )
        except requests.exceptions.SSLError:
            try:
                response = self._session.request(
                    method, url, headers=headers,
                    timeout=self.timeout, allow_redirects=False, verify=False,
                )
            except Exception:
                return None
        except Exception:
            return None

        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_creds  = response.headers.get("Access-Control-Allow-Credentials")
        allow_methods = response.headers.get("Access-Control-Allow-Methods")
        allow_headers = response.headers.get("Access-Control-Allow-Headers")

        if not allow_origin:
            return None  # No CORS headers → nothing to report

        return self._classify(
            url, origin, allow_origin, allow_creds,
            allow_methods, allow_headers,
        )

    def _classify(
        self,
        url: str,
        origin_sent: str,
        allow_origin: str,
        allow_creds: str | None,
        allow_methods: str | None,
        allow_headers: str | None,
    ) -> CORSFinding | None:
        """
        Classify the CORS response into a severity bucket.

        Priority order (highest → lowest):
          1. CRITICAL  – wildcard + credentials (spec-invalid but some servers)
          2. CRITICAL  – reflected arbitrary origin + credentials
          3. HIGH      – reflected arbitrary origin (no credentials)
          4. HIGH      – null origin allowed + credentials
          5. MEDIUM    – wildcard origin (no credentials, public API acceptable)
          6. MEDIUM    – null origin allowed (no credentials)
          7. LOW       – sub-domain / suffix-match reflected
          8. None      – safe / expected
        """
        creds_true = (allow_creds or "").lower() == "true"
        is_wildcard = allow_origin == "*"
        is_reflected = allow_origin == origin_sent and origin_sent not in ("*",)
        is_null = allow_origin == "null"
        is_suffix_bypass = (
            not is_wildcard
            and not is_reflected
            and not is_null
            and allow_origin.endswith(origin_sent.lstrip("https://"))
        )

        # --- 1. Wildcard + credentials (CORS spec forbids this, but some
        #        misconfigured servers do it anyway via custom middleware) ---
        if is_wildcard and creds_true:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.CRITICAL,
                title="Wildcard origin with credentials",
                description=(
                    "The server responds with Access-Control-Allow-Origin: * "
                    "and Access-Control-Allow-Credentials: true. Browsers "
                    "block this combination per spec, but the configuration "
                    "signals a fundamental misunderstanding of CORS security "
                    "that may be exploitable through non-browser clients or "
                    "future spec changes."
                ),
                recommendation=(
                    "Never combine a wildcard origin with credentials=true. "
                    "Maintain an explicit allowlist of trusted origins and "
                    "reflect only those, not arbitrary inputs."
                ),
            )

        # --- 2. Reflected arbitrary origin + credentials (CRITICAL) -------
        if is_reflected and creds_true:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.CRITICAL,
                title="Arbitrary origin reflected with credentials",
                description=(
                    f"The server reflects the attacker-supplied origin "
                    f"'{origin_sent}' in Access-Control-Allow-Origin and also "
                    f"sets Access-Control-Allow-Credentials: true. An attacker "
                    f"can host a page on that origin, make cross-origin "
                    f"requests with the victim's cookies or tokens, and read "
                    f"the response. This is exploitable with no user interaction "
                    f"beyond visiting the attacker's page."
                ),
                recommendation=(
                    "Maintain an explicit server-side allowlist of trusted "
                    "origins. Validate the Origin header against the list "
                    "before reflecting it. Never echo arbitrary origins when "
                    "credentials are enabled."
                ),
            )

        # --- 3. Reflected arbitrary origin, no credentials (HIGH) ----------
        if is_reflected:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.HIGH,
                title="Arbitrary origin reflected (no credentials)",
                description=(
                    f"The server reflects the attacker-supplied origin "
                    f"'{origin_sent}' in Access-Control-Allow-Origin without "
                    f"requiring credentials. Public data endpoints may be "
                    f"acceptable, but if any endpoint returns user-specific "
                    f"data, this allows cross-origin data theft."
                ),
                recommendation=(
                    "Replace wildcard / reflected policies with an explicit "
                    "origin allowlist. Audit whether endpoints return any "
                    "user-specific data under this CORS policy."
                ),
            )

        # --- 4. Null origin + credentials (HIGH) ---------------------------
        if is_null and creds_true:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.HIGH,
                title="Null origin allowed with credentials",
                description=(
                    "The server accepts the 'null' origin with credentials "
                    "enabled. The null origin is sent by sandboxed iframes, "
                    "data: URIs, and local HTML files, giving attackers a "
                    "simple attack vector via a sandboxed iframe on any page."
                ),
                recommendation=(
                    "Remove 'null' from the origin allowlist. It is never a "
                    "legitimate trusted origin for production APIs."
                ),
            )

        # --- 5. Wildcard origin, no credentials (MEDIUM) -------------------
        if is_wildcard:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.MEDIUM,
                title="Wildcard origin (public endpoint)",
                description=(
                    "Access-Control-Allow-Origin: * allows any origin to read "
                    "the response. Without credentials this is safe for "
                    "genuinely public APIs, but risks data exposure if "
                    "authentication is added later or if the endpoint is "
                    "mistakenly widened."
                ),
                recommendation=(
                    "Verify this endpoint is intentionally fully public. "
                    "If so, document the decision. If not, restrict to an "
                    "explicit origin allowlist."
                ),
            )

        # --- 6. Null origin, no credentials (MEDIUM) -----------------------
        if is_null:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.MEDIUM,
                title="Null origin allowed",
                description=(
                    "The server accepts the 'null' origin. While credentials "
                    "are not enabled, allowing null opens the door to "
                    "sandboxed-iframe attacks."
                ),
                recommendation="Remove 'null' from the origin allowlist.",
            )

        # --- 7. Suffix-match bypass (LOW) ----------------------------------
        if is_suffix_bypass:
            return CORSFinding(
                endpoint=url,
                origin_sent=origin_sent,
                allow_origin=allow_origin,
                allow_credentials=allow_creds,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                severity=CORSSeverity.LOW,
                title="Potential suffix-match origin bypass",
                description=(
                    f"The server returned '{allow_origin}' in response to "
                    f"origin '{origin_sent}'. This may indicate a naive "
                    f"suffix-match allowlist that can be bypassed by "
                    f"registering a domain ending in a trusted suffix "
                    f"(e.g., eviltrusted.com when trusted.com is allowed)."
                ),
                recommendation=(
                    "Use exact-match comparison for allowed origins, not "
                    "substring or suffix matching."
                ),
            )

        return None  # Looks safe – no finding to report7
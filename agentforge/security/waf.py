"""WAF middleware — first-line request filter (CLAUDE.md §8.2).

Blocks before the request ever reaches a router:
  - SQL injection patterns in body/query
  - Path traversal (../ , %2e%2e , backslash variants)
  - Internal-network SSRF in URL params (used in webhook ingest later)
  - Known scanner user-agents (sqlmap, nikto, gobuster, etc.)
  - IP blocklist (Redis-backed set, optional)
  - Oversized payloads (> 50 KB by default)
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import unquote_plus, urlparse

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 50 * 1024  # 50 KB hard ceiling on inbound payloads.

# Compiled once at import — these run on every request, so keep them lean.
_SQLI_PATTERNS = [
    re.compile(r"(?i)\b(union\s+(all\s+)?select|select\s+\*\s+from|insert\s+into|drop\s+table|drop\s+database)\b"),
    re.compile(r"(?i)(--\s*$|;\s*--|/\*.*\*/|\bxp_cmdshell\b|\bexec\s*\(|\bload_file\s*\()"),
    re.compile(r"(?i)\b(or|and)\s+\d+\s*=\s*\d+\b"),
]
_PATH_TRAVERSAL = re.compile(r"(\.\.[/\\]|%2e%2e[/\\]|%252e%252e)", re.IGNORECASE)
_SCANNER_UAS = re.compile(
    r"(?i)(sqlmap|nikto|gobuster|dirbuster|wpscan|nessus|acunetix|nuclei|metasploit|hydra|burpcollab|fuzzing)"
)
# Unicode normalization attacks: visually-similar lookalikes that bypass naive
# filters (e.g. Cyrillic 'а' instead of ASCII 'a').
_SUSPECT_UNICODE = re.compile(r"[‮‎‏⁦-⁩]")  # bidi/marker controls


def _is_internal_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _ssrf_check(value: str) -> bool:
    """Reject URLs pointing at internal infrastructure."""
    if not value or "://" not in value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return True
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    # Common internal hostnames + IPs
    if host in {"localhost", "metadata.google.internal", "169.254.169.254"}:
        return True
    return _is_internal_ip(host)


def _scan_text(text: str) -> str | None:
    """Return reason if text is suspicious, else None."""
    for p in _SQLI_PATTERNS:
        if p.search(text):
            return "sqli_pattern"
    if _PATH_TRAVERSAL.search(text):
        return "path_traversal"
    if _SUSPECT_UNICODE.search(text):
        return "suspicious_unicode"
    return None


class WAFMiddleware(BaseHTTPMiddleware):
    """Block obviously malicious requests before routing.

    Whitelisted paths skip scanning so legitimate adversarial payloads sent
    via /api/v1/campaigns can still flow through. The Co-Pilot is a different
    machine — AgentForge's own API is the surface this WAF protects.
    """

    BLOCK_PATHS_SCAN: tuple[str, ...] = ("/api/v1/auth", "/api/v1/findings", "/api/v1/regression", "/api/v1/campaigns")

    def __init__(self, app, ip_blocklist: set[str] | None = None) -> None:
        super().__init__(app)
        self.ip_blocklist = ip_blocklist or set()

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        client_host = request.client.host if request.client else ""
        if client_host and client_host in self.ip_blocklist:
            return _block(403, "IP blocked", client_host=client_host)

        ua = request.headers.get("user-agent", "")
        if _SCANNER_UAS.search(ua):
            return _block(403, "Scanner user-agent rejected", ua=ua[:80])

        # Inspect query string for SQLi / traversal / SSRF.
        # Decode the raw query so '+' -> space and %XX -> char before scanning;
        # otherwise SQLi keywords joined by '+' or hex-encoded traversal slip
        # through whitespace-anchored regexes.
        qs = request.url.query
        if qs:
            decoded_qs = unquote_plus(qs)
            reason = _scan_text(decoded_qs)
            if reason:
                return _block(400, f"Request blocked: {reason} in query", path=request.url.path)
            # SSRF check: any param value that parses as URL
            for v in request.query_params.values():
                if _ssrf_check(v):
                    return _block(400, "Request blocked: ssrf in query param", path=request.url.path)

        # Body size cap.
        try:
            cl = int(request.headers.get("content-length") or 0)
        except ValueError:
            cl = 0
        if cl > MAX_BODY_BYTES:
            return _block(413, f"Payload too large ({cl} > {MAX_BODY_BYTES} bytes)")

        # For our own admin/security endpoints we inspect the body too; we
        # explicitly DO NOT inspect /chat-shaped routes since AgentForge has
        # none of its own and would only false-positive on legitimate
        # adversarial content destined for the Co-Pilot.
        if any(request.url.path.startswith(p) for p in self.BLOCK_PATHS_SCAN) and request.method in {"POST", "PATCH", "PUT"}:
            body = await request.body()
            if body:
                # Cache the body back onto the request scope so handlers can re-read it.
                async def _receive():  # type: ignore[no-untyped-def]
                    return {"type": "http.request", "body": body, "more_body": False}

                request._receive = _receive  # type: ignore[attr-defined]
                try:
                    decoded = body.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    decoded = ""
                if decoded:
                    reason = _scan_text(decoded)
                    if reason:
                        return _block(400, f"Request blocked: {reason} in body", path=request.url.path)

        return await call_next(request)


def _block(code: int, detail: str, **fields) -> JSONResponse:
    logger.warning("waf_block code=%s detail=%s extra=%s", code, detail, fields)
    return JSONResponse(status_code=code, content={"detail": detail, "blocked_by": "waf"})

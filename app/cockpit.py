"""Operator Security Cockpit: static HTML shell, assets and hardening headers.

The cockpit is a zero-build, CSP-strict UI: one semantic HTML document plus
external CSS and native ES modules under ``app/static``. No inline script,
style or ``on*=`` handler is ever emitted, so the policy below can forbid
them entirely.
"""

from functools import lru_cache
from pathlib import Path

from fastapi.responses import HTMLResponse

COCKPIT_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = COCKPIT_DIR / "templates" / "cockpit.html"
STATIC_DIR = COCKPIT_DIR / "static"

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "font-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    )
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@lru_cache(maxsize=1)
def cockpit_html() -> str:
    """Return the cockpit document (read once; it is immutable at runtime)."""
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def cockpit_response() -> HTMLResponse:
    """Render the cockpit shell with strict CSP and anti-framing headers."""
    return HTMLResponse(content=cockpit_html(), headers=SECURITY_HEADERS)

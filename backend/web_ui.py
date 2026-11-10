"""
PrivacyGuard Web UI Provider
Serves the authoritative cybersecurity web application frontend for production and Vercel serverless deployments.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_HTML_PATH = BASE_DIR / "frontend" / "static" / "index.html"

_CACHED_HTML: str = ""


def get_frontend_html() -> str:
    """
    Returns the complete Single Page Application HTML for PrivacyGuard.
    Caches the content in memory for serverless performance.
    """
    global _CACHED_HTML
    if _CACHED_HTML:
        return _CACHED_HTML

    if STATIC_HTML_PATH.exists():
        try:
            _CACHED_HTML = STATIC_HTML_PATH.read_text(encoding="utf-8")
            return _CACHED_HTML
        except Exception:
            pass

    # Fallback to search in local directories
    alt_paths = [
        Path("frontend/static/index.html"),
        Path("static/index.html"),
        Path(__file__).parent / "static" / "index.html",
    ]
    for p in alt_paths:
        if p.exists():
            try:
                _CACHED_HTML = p.read_text(encoding="utf-8")
                return _CACHED_HTML
            except Exception:
                continue

    return "<h1>PrivacyGuard Frontend — Loading Failed</h1>"

"""
Vercel Serverless Function entrypoint.
Imports and surfaces the authoritative FastAPI application instance with
automatic ASGI path normalization for Vercel serverless rewrites.
"""
from backend.main import app as fastapi_app


async def app(scope, receive, send):
    """
    ASGI middleware ensuring that Vercel serverless rewrites to /api/index
    correctly map to the application's root and nested endpoints.
    """
    if scope.get("type") == "http":
        path = scope.get("path", "")
        if path == "/api/index" or path == "/api/index/":
            scope["path"] = "/"
        elif path.startswith("/api/index/"):
            scope["path"] = path[len("/api/index"):]
    await fastapi_app(scope, receive, send)


# Expose both app and handler for maximum compatibility with Vercel Serverless
handler = app

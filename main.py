"""
Root entrypoint for deployment environments that scan for top-level main.py.
Imports and surfaces the authoritative FastAPI application instance.
"""
from backend.main import app

if __name__ == "__main__":
    import uvicorn
    from backend.config import settings
    uvicorn.run("backend.main:app", host=settings.BACKEND_HOST, port=settings.BACKEND_PORT)

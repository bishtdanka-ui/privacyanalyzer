import uvicorn
from backend.config import settings

if __name__ == "__main__":
    print(f"Starting FastAPI Backend Server on http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}...")
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )


import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import engine, Base, SessionLocal
from backend.models.user import User
from backend.security.hashing import hash_password
from backend.routers import auth, analysis, admin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend")

def init_db_and_seed():
    """
    Create tables and seed initial administrator account if needed.
    """
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.email == settings.DEFAULT_ADMIN_EMAIL.lower()).first()
        if not admin_user:
            logger.info(f"Seeding default administrator account: {settings.DEFAULT_ADMIN_EMAIL}")
            admin_user = User(
                email=settings.DEFAULT_ADMIN_EMAIL.lower(),
                full_name="System Administrator",
                password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
                email_verified=True
            )
            db.add(admin_user)
            db.commit()
            logger.info("Default administrator account initialized.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
        db.rollback()
    finally:
        db.close()

init_db_and_seed()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Explainable Cybersecurity Application Privacy & Permission Analyzer API (PS02)",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")

@app.get("/")
def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "docs_url": "/docs",
        "api_v1": "/api/v1"
    }

@app.get("/health")
@app.get("/api/v1/health")
def healthcheck():
    return {"status": "healthy", "database": "connected"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

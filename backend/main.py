import os
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, status, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.database import engine, Base, SessionLocal, check_db_connection
from backend.models.user import User
from backend.security.hashing import hash_password
from backend.routers import auth, analysis, admin
from backend.web_ui import get_frontend_html, STATIC_HTML_PATH
from knowledge_base.lookup_service import permission_lookup_service

# Structured Application Logging Setup
logging.basicConfig(
    level=logging.INFO if settings.ENV == "production" else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("privacyguard.backend")


def init_db_and_seed():
    """
    Initialize database schema and seed default administrator account if needed.
    """
    try:
        logger.info("Verifying database schema...")
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
                logger.info("Administrator account provisioned successfully.")
        except Exception as e:
            logger.error(f"Error during admin account provisioning: {e}")
            db.rollback()
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Database initialization deferred or encountered error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Proper startup and graceful shutdown handling.
    """
    # --- STARTUP ---
    try:
        logger.info(f"Starting {settings.PROJECT_NAME} (v{settings.APP_VERSION}) in [{settings.ENV.upper()}] mode")
        init_db_and_seed()
        
        # Pre-check knowledge base entries
        entry_count = permission_lookup_service.get_entry_count()
        logger.info(f"Knowledge Base active with {entry_count} verified Android permissions.")
        
        # Verify report output directory write permissions
        storage_writable = os.access(settings.REPORT_OUTPUT_DIR, os.W_OK)
        if storage_writable:
            logger.info(f"Report storage verified at {settings.REPORT_OUTPUT_DIR.resolve()}")
        else:
            logger.warning(f"Report storage path {settings.REPORT_OUTPUT_DIR} is NOT writable!")
    except Exception as e:
        logger.error(f"Lifespan startup encountered non-fatal error: {e}")
    
    yield
    
    # --- SHUTDOWN ---
    try:
        logger.info("Gracefully shutting down PrivacyGuard API services...")
        engine.dispose()
        logger.info("Database connection pool disposed. Shutdown complete.")
    except Exception as e:
        logger.error(f"Lifespan shutdown error: {e}")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Explainable Cybersecurity Application Privacy & Permission Analyzer API (PS02)",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS Configuration
cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(analysis.analyze_router, prefix="/api/v1")
app.include_router(analysis.analyses_router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")


# Optional static files mounting
static_dir = STATIC_HTML_PATH.parent
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api/index/", response_class=HTMLResponse)
def root(request: Request):
    """
    Serves the complete Privacy Analyzer frontend to web visitors.
    If the caller explicitly requests application/json, returns API metadata.
    """
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return JSONResponse({
            "status": "online",
            "service": settings.PROJECT_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENV,
            "docs_url": "/docs",
            "api_v1": "/api/v1"
        })
    return HTMLResponse(content=get_frontend_html(), status_code=200)


@app.get("/api/info")
def api_info():
    """Programmatic API service descriptor."""
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENV,
        "docs_url": "/docs",
        "api_v1": "/api/v1"
    }


@app.get("/health", status_code=status.HTTP_200_OK)
@app.get("/api/v1/health", status_code=status.HTTP_200_OK)
def healthcheck(response: Response = None):
    """
    Deep application health-check endpoint probing database connectivity,
    knowledge base state, and report storage write accessibility.
    """
    if response is None:
        response = Response()
    db_ok = check_db_connection()
    kb_count = permission_lookup_service.get_entry_count()
    kb_ok = kb_count > 0
    storage_ok = os.access(settings.REPORT_OUTPUT_DIR, os.W_OK)

    is_healthy = db_ok and kb_ok and storage_ok
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    db_dialect = engine.dialect.name

    return {
        "status": "healthy" if is_healthy else "degraded",
        "environment": settings.ENV,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": {
                "status": "connected" if db_ok else "unreachable",
                "engine": db_dialect
            },
            "knowledge_base": {
                "status": "loaded" if kb_ok else "missing",
                "entries": kb_count
            },
            "report_storage": {
                "status": "writable" if storage_ok else "read_only",
                "path": str(settings.REPORT_OUTPUT_DIR.resolve())
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=(settings.ENV == "development")
    )

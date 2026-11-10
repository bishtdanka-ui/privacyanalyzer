import os
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger("backend.config")

# Load .env file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Explainable Application Privacy and Permission Analyzer")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    ENV: str = os.getenv("ENV", "development").lower().strip()
    
    # Cryptographic Secret Key
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-this-in-production-cybersecurity-ps02")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    
    # Token Lifespans
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    REFRESH_TOKEN_REMEMBER_DAYS: int = int(os.getenv("REFRESH_TOKEN_REMEMBER_DAYS", "30"))
    
    # Brute-force & Throttle Security
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", "15"))
    
    # Environment Detection (e.g. Vercel Serverless)
    IS_VERCEL: bool = os.getenv("VERCEL") == "1"

    # Database Configuration (PostgreSQL / SQLite)
    _raw_db = os.getenv("DATABASE_URL", "").strip()
    if IS_VERCEL:
        # In Vercel serverless: read-only root requires /tmp for SQLite, and postgresql:// for Postgres
        if not _raw_db or "sqlite" in _raw_db and "/tmp" not in _raw_db:
            _db_url = "sqlite:////tmp/privacy_analyzer.db"
        elif _raw_db.startswith("postgres://"):
            _db_url = _raw_db.replace("postgres://", "postgresql://", 1)
        else:
            _db_url = _raw_db
    else:
        _db_url = _raw_db if _raw_db else f"sqlite:///{BASE_DIR / 'privacy_analyzer.db'}"
        if _db_url.startswith("postgres://"):
            _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    
    DATABASE_URL: str = _db_url
    
    # File Upload & Payload Size Limits
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "5"))
    MAX_MANIFEST_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    MAX_POLICY_LENGTH: int = int(os.getenv("MAX_POLICY_LENGTH", "1000000"))
    
    # Default Admin Seed (Configurable via Environment)
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@privacyanalyzer.local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "AdminSecurePassword123!")
    
    # Networking & CORS
    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "127.0.0.1")
    BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
    FRONTEND_PORT: int = int(os.getenv("FRONTEND_PORT", "8501"))
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")
    
    # Paths & Knowledge Base (Use /tmp for writable paths in serverless environments)
    if IS_VERCEL:
        _default_reports = Path("/tmp/reports")
        _default_uploads = Path("/tmp/uploads")
        _raw_reports = os.getenv("REPORT_OUTPUT_DIR", "").strip()
        _raw_uploads = os.getenv("UPLOAD_TEMP_DIR", "").strip()
        REPORT_OUTPUT_DIR: Path = Path(_raw_reports) if (_raw_reports and _raw_reports.startswith("/tmp")) else _default_reports
        UPLOAD_TEMP_DIR: Path = Path(_raw_uploads) if (_raw_uploads and _raw_uploads.startswith("/tmp")) else _default_uploads
    else:
        REPORT_OUTPUT_DIR: Path = Path(os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports")))
        UPLOAD_TEMP_DIR: Path = Path(os.getenv("UPLOAD_TEMP_DIR", str(BASE_DIR / "uploads")))
    KB_PATH: Path = BASE_DIR / "knowledge_base" / "android_permissions.json"

    def __init__(self):
        try:
            self.REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        try:
            self.UPLOAD_TEMP_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        
        # Security validation for production
        if self.ENV == "production":
            if "super-secret-key" in self.SECRET_KEY:
                logger.warning(
                    "SECURITY WARNING: Production mode enabled with default SECRET_KEY! "
                    "Generate a cryptographically secure key via: "
                    "python -c 'import secrets; print(secrets.token_urlsafe(64))'"
                )


settings = Settings()

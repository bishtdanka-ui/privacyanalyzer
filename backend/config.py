import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Explainable Application Privacy and Permission Analyzer")
    ENV: str = os.getenv("ENV", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-this-in-production-cybersecurity-ps02")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    
    # Token Lifespans
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # Short-lived access token
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))      # Standard refresh token
    REFRESH_TOKEN_REMEMBER_DAYS: int = int(os.getenv("REFRESH_TOKEN_REMEMBER_DAYS", "30")) # Extended remember-me session
    
    # Brute-force & Throttle Security
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", "15"))
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'privacy_analyzer.db'}")
    
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@privacyanalyzer.local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "AdminSecurePassword123!")
    
    REPORT_OUTPUT_DIR: Path = Path(os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports")))
    KB_PATH: Path = BASE_DIR / "data" / "android_permissions_kb.json"

    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

settings = Settings()


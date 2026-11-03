import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Explainable Application Privacy and Permission Analyzer")
    ENV: str = os.getenv("ENV", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'privacy_analyzer.db'}")
    
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@privacyanalyzer.local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "AdminSecurePassword123!")
    
    REPORT_OUTPUT_DIR: Path = Path(os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports")))
    KB_PATH: Path = BASE_DIR / "data" / "android_permissions_kb.json"

    # Ensure reports directory exists
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

settings = Settings()

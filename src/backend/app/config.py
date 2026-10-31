"""Configuration module for VIGILANCE digital forensics platform."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    APP_NAME: str = "VIGILANCE Digital Forensics Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Storage paths
    EVIDENCE_STORAGE_PATH: str = os.getenv(
        "EVIDENCE_STORAGE_PATH",
        str((PROJECT_ROOT / "evidence_storage").resolve())
    )
    REPORTS_PATH: str = os.getenv(
        "REPORTS_PATH",
        str((PROJECT_ROOT / "generated_reports").resolve())
    )
    SAMPLE_DATA_PATH: str = os.getenv(
        "SAMPLE_DATA_PATH",
        str((PROJECT_ROOT / "sample_data").resolve())
    )

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{str((BACKEND_DIR / 'vigilance.db').resolve())}"
    )

    # Upload constraints
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
    MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024
    ALLOWED_EXTENSIONS: set = {".csv", ".json", ".log", ".txt"}

    # CORS
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()

# Direct constant exports as requested by specifications
EVIDENCE_STORAGE_PATH = settings.EVIDENCE_STORAGE_PATH
REPORTS_PATH = settings.REPORTS_PATH
DATABASE_URL = settings.DATABASE_URL
MAX_FILE_SIZE_MB = settings.MAX_FILE_SIZE_MB
ALLOWED_EXTENSIONS = settings.ALLOWED_EXTENSIONS

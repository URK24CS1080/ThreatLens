"""
Configuration settings for the Website Security & Threat Intelligence Analyzer.
Loads environment variables and provides sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Paths
    BASE_DIR = BASE_DIR
    # Database Configuration (MongoDB primary with SQLite fallback)
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/threatlens").strip()
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "threatlens").strip()
    DATABASE_PATH = BASE_DIR / "database" / "analyzer.db"
    REPORTS_DIR = BASE_DIR / "reports"
    
    # Network & Scanning Security Controls
    MAX_SCAN_TIMEOUT = int(os.getenv("MAX_SCAN_TIMEOUT", "6"))  # seconds
    MAX_CONTENT_SIZE_BYTES = int(os.getenv("MAX_CONTENT_SIZE_BYTES", str(2 * 1024 * 1024)))  # 2MB max download
    MAX_REDIRECTS = 5
    ALLOW_PORT_SCAN = os.getenv("ALLOW_PORT_SCAN", "True").lower() in ("true", "1", "yes")
    
    # Default common ports checked during authorized service discovery
    DEFAULT_COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
    
    # Threat Intelligence & AI APIs
    SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
    AI_PROVIDER = os.getenv("AI_PROVIDER", "auto").strip().lower()  # auto, gemini, openai, builtin


# Ensure runtime directories exist
Config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
Config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


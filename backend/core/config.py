import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load local .env if available
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR.parent / ".env")

class Settings:
    PROJECT_NAME: str = "PhishGuard AI"
    PROJECT_SUBTITLE: str = "AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # CORS
    _raw_cors = os.getenv("CORS_ORIGINS", "*")
    CORS_ORIGINS: list[str] = [
        origin.strip() for origin in _raw_cors.split(",") if origin.strip()
    ] if _raw_cors != "*" else ["*"]
    
    # Storage paths
    DATA_DIR: Path = BASE_DIR / "data"
    DATASETS_DIR: Path = DATA_DIR / "datasets"
    CASES_FILE: Path = DATA_DIR / "cases.json"
    ML_DIR: Path = BASE_DIR / "ml"
    MODELS_DIR: Path = ML_DIR / "models"
    MODEL_PATH: Path = MODELS_DIR / "phishing_model.joblib"
    VECTORIZER_PATH: Path = MODELS_DIR / "vectorizer.joblib"
    METRICS_PATH: Path = MODELS_DIR / "metrics.json"
    
    # Risk Score thresholds
    RISK_CRITICAL: int = 76
    RISK_HIGH: int = 51
    RISK_MEDIUM: int = 26
    
    # Organization & Domain Forensics
    INTERNAL_DOMAINS: list[str] = ["phishguardai.com"]
    
    # NVIDIA Nemotron 550B Reasoning LLM Integration
    NVIDIA_BASE_URL: str = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    NVIDIA_API_KEY: str = os.getenv("NVIDIA_API_KEY", "")
    NVIDIA_MODEL: str = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
    
    # API Keys (Optional External Integrations)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    MAXMIND_LICENSE_KEY: str = os.getenv("MAXMIND_LICENSE_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

settings = Settings()
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
(settings.DATA_DIR / "samples").mkdir(parents=True, exist_ok=True)
(settings.DATA_DIR / "datasets").mkdir(parents=True, exist_ok=True)

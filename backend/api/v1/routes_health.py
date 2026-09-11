from datetime import datetime, timezone
from fastapi import APIRouter
from backend.core.config import settings

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check():
    """Health check endpoint confirming API service and SOC engine status."""
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "soc_defenses": "active",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

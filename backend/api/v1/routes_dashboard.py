from fastapi import APIRouter
from backend.services.case_store import case_store
from backend.models.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_statistics():
    """Returns SOC KPI metrics, charts data, and recent threat activity."""
    return case_store.get_dashboard_stats()

@router.get("/recent-threats")
def get_recent_threats(limit: int = 10):
    """Returns recent threat detections for the live activity feed."""
    return case_store.list_cases()[:limit]

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from backend.services.case_store import case_store
from backend.models.schemas import InvestigationCase

router = APIRouter(prefix="/investigations", tags=["Investigations"])

class StatusUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = ""

@router.get("", response_model=list[InvestigationCase])
def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status (Open, Triaged, Closed, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    search: Optional[str] = Query(None, description="Search term in subject, sender, IP, or case ID")
):
    """Retrieves SOC investigation cases with optional filtering and search."""
    return case_store.list_cases(status=status, severity=severity, query=search)

@router.get("/{case_id}", response_model=InvestigationCase)
def get_investigation_case(case_id: str):
    """Retrieves single investigation case details."""
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return case

@router.patch("/{case_id}/status", response_model=InvestigationCase)
def update_case_status(case_id: str, payload: StatusUpdateRequest):
    """Updates case triage status (Open, Triaged, Closed, Quarantined)."""
    updated = case_store.update_case_status(case_id, payload.status, payload.notes or "")
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated

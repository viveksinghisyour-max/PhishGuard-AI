from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel
from backend.services.case_store import case_store
from backend.services.threat_graph_service import threat_graph_service
from backend.models.schemas import (
    InvestigationCase, 
    CaseNote, 
    ContainmentAction, 
    CaseNoteCreate, 
    ContainmentActionCreate, 
    PromoteAnalysisRequest,
    ThreatCorrelationGraph
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])

class StatusUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = ""

class AnalystUpdateRequest(BaseModel):
    assigned_analyst: str

@router.get("", response_model=list[InvestigationCase])
def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status (Open, Triaged, Closed, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    search: Optional[str] = Query(None, description="Search term in subject, sender, IP, or case ID")
):
    """Retrieves SOC investigation cases with optional filtering and search."""
    return case_store.list_cases(status=status, severity=severity, query=search)

@router.get("/correlation-graph", response_model=ThreatCorrelationGraph)
def get_global_correlation_graph():
    """Generates the multi-dimensional global threat correlation topology graph."""
    return threat_graph_service.build_global_correlation_graph()

@router.post("/promote", response_model=InvestigationCase)
def promote_analysis_to_case(payload: PromoteAnalysisRequest = Body(...)):
    """Promotes an analyzed email result into a formal SOC investigation case."""
    return case_store.promote_analysis_to_case(payload)

@router.get("/{case_id}", response_model=InvestigationCase)
def get_investigation_case(case_id: str):
    """Retrieves single investigation case details."""
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return case

@router.get("/{case_id}/graph", response_model=ThreatCorrelationGraph)
def get_case_correlation_subgraph(case_id: str):
    """Retrieves localized 2-hop threat correlation neighborhood for a specific case."""
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return threat_graph_service.build_case_subgraph(case_id)

@router.patch("/{case_id}/status", response_model=InvestigationCase)
def update_case_status(case_id: str, payload: StatusUpdateRequest):
    """Updates case triage status (Open, Triaged, Closed, Quarantined)."""
    updated = case_store.update_case_status(case_id, payload.status, payload.notes or "")
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated

@router.patch("/{case_id}/analyst", response_model=InvestigationCase)
def update_case_analyst(case_id: str, payload: AnalystUpdateRequest):
    """Assigns case to a specific SOC analyst."""
    updated = case_store.update_case_analyst(case_id, payload.assigned_analyst)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated

@router.post("/{case_id}/notes", response_model=CaseNote)
def add_case_note(case_id: str, payload: CaseNoteCreate):
    """Appends an analyst investigation note to the case timeline."""
    note = case_store.add_note(case_id, payload.author, payload.text)
    if not note:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return note

@router.post("/{case_id}/containment", response_model=ContainmentAction)
def execute_containment_action(case_id: str, payload: ContainmentActionCreate):
    """Executes an active SOC containment action (block IP, quarantine inbox, etc.)."""
    action = case_store.execute_containment(
        case_id=case_id,
        action_type=payload.action_type,
        target=payload.target,
        executed_by=payload.executed_by,
        details=payload.details
    )
    if not action:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return action

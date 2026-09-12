"""
PhishGuard AI — Interactive MITRE ATT&CK® Enterprise Matrix Routes
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from backend.models.schemas import MitreMatrixResponse, MitreHeatmapResponse
from backend.services.mitre_matrix_service import mitre_matrix_service

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK Matrix"])

@router.get("/matrix", response_model=MitreMatrixResponse)
def get_mitre_matrix():
    """Retrieves the full MITRE ATT&CK Enterprise Matrix taxonomy for email & cyber attacks."""
    return mitre_matrix_service.get_matrix()

@router.get("/heatmap", response_model=MitreHeatmapResponse)
def get_mitre_heatmap():
    """Calculates active detection frequencies, severities, and case associations across techniques."""
    return mitre_matrix_service.calculate_heatmap()

@router.get("/export-layer")
def export_navigator_layer():
    """Generates standard MITRE ATT&CK® Navigator Layer JSON (v4.5) export."""
    layer = mitre_matrix_service.export_navigator_layer()
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": "attachment; filename=phishguard-mitre-attack-layer.json"}
    )

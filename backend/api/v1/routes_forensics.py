import json
from fastapi import APIRouter, HTTPException, Response
from backend.services.forensic_dossier_service import forensic_dossier_service
from backend.services.case_store import case_store
from backend.models.schemas import (
    ForensicDossier,
    ChainOfCustodyVerification,
    DefensiveRulesResponse
)

router = APIRouter(prefix="/forensics", tags=["Forensics"])

@router.get("/dossier/{case_id}", response_model=ForensicDossier)
def get_forensic_dossier(case_id: str):
    """
    Retrieves the complete, formal Forensic Incident Dossier for a case,
    including cryptographic digests, chain of custody ledger, relay hops, and IOCs.
    """
    dossier = forensic_dossier_service.build_forensic_dossier(case_id)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return dossier

@router.post("/verify-chain/{case_id}", response_model=ChainOfCustodyVerification)
def verify_custody_chain(case_id: str):
    """
    Executes a cryptographic verification pass across the sequential SHA-256 Merkle ledger
    for the specified case, verifying that no block or link has been tampered with.
    """
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    blocks = forensic_dossier_service.generate_chain_of_custody(case)
    verification = forensic_dossier_service.verify_chain_of_custody(blocks)
    return verification

@router.get("/export/stix/{case_id}")
def export_stix_bundle(case_id: str):
    """
    Exports case threat intelligence and IOCs as an OASIS STIX 2.1 compliant JSON bundle.
    """
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    bundle = forensic_dossier_service.generate_stix_bundle(case)
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=stix21-threat-bundle-{case_id}.json"}
    )

@router.get("/export/csv/{case_id}")
def export_ioc_csv(case_id: str):
    """
    Exports extracted indicators of compromise (IOCs) as a downloadable CSV table.
    """
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    csv_content = forensic_dossier_service.generate_ioc_csv(case)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=iocs-{case_id}.csv"}
    )

@router.get("/export/rules/{case_id}", response_model=DefensiveRulesResponse)
def get_defensive_rules(case_id: str):
    """
    Generates automated Suricata NIDS rules, Snort rules, and YARA signatures
    based on the artifacts and indicators extracted from the case.
    """
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    return forensic_dossier_service.generate_defensive_rules(case)

@router.get("/export/html/{case_id}")
def export_html_report(case_id: str):
    """
    Generates a standalone, print-ready HTML forensic incident report with cryptographic seal.
    """
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    
    html = forensic_dossier_service.generate_html_dossier(case_id)
    return Response(content=html, media_type="text/html")

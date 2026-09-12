"""
PhishGuard AI — Threat Intelligence & Multi-Source IOC Lookup Routes
"""

from fastapi import APIRouter, HTTPException
from backend.models.schemas import IOCLookupRequest, IOCLookupResponse, ThreatFeedSyncStatus
from backend.services.threat_intel_service import threat_intel_service

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

@router.post("/lookup", response_model=IOCLookupResponse)
def lookup_ioc(payload: IOCLookupRequest):
    """Sub-millisecond enriched multi-type threat intelligence lookup (IP, Domain, URL, Hash)."""
    if not payload.query or not payload.query.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty")
    return threat_intel_service.lookup_ioc(payload.query, payload.type)

@router.get("/feeds/status", response_model=ThreatFeedSyncStatus)
def get_threat_feeds_status():
    """Returns active threat feed provider synchronization metrics and statistics."""
    return threat_intel_service.get_sync_status()

@router.post("/feeds/sync", response_model=ThreatFeedSyncStatus)
def sync_threat_feeds():
    """Triggers on-demand synchronization and indicator refresh across all threat feed providers."""
    return threat_intel_service.sync_feeds()

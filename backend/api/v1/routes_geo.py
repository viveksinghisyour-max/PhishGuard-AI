from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Body
from backend.models.schemas import GeoLocationInfo, RelayHop
from backend.services.geolocation_service import geo_service

router = APIRouter(prefix="/geo", tags=["geolocation"])

@router.get("/lookup/{ip}", response_model=GeoLocationInfo)
def lookup_ip_geolocation(ip: str):
    """Resolves geographic coordinates, ISP, ASN, and risk tags for a public IP."""
    geo = geo_service.resolve_ip(ip)
    if not geo:
        raise HTTPException(status_code=404, detail=f"IP address '{ip}' is private RFC 1918 or unresolvable")
    return geo

@router.post("/trajectory")
def calculate_relay_trajectory(hops: List[RelayHop] = Body(...)):
    """
    Computes great-circle geodesic transmission distance and builds
    an ordered Leaflet trajectory from origin host to destination gateway.
    """
    if not hops:
        raise HTTPException(status_code=400, detail="Empty relay hops provided")
    
    trajectory_data = geo_service.build_relay_trajectory(hops)
    return trajectory_data

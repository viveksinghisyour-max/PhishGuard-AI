import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.geolocation_service import GeolocationService, geo_service
from backend.models.schemas import RelayHop

client = TestClient(app)

def test_private_ip_detection():
    """Verify private and loopback subnets are identified correctly."""
    assert GeolocationService.is_private_ip("127.0.0.1") is True
    assert GeolocationService.is_private_ip("10.0.1.42") is True
    assert GeolocationService.is_private_ip("192.168.0.1") is True
    assert GeolocationService.is_private_ip("172.16.0.5") is True
    assert GeolocationService.is_private_ip("185.220.101.44") is False
    assert GeolocationService.is_private_ip("8.8.8.8") is False

def test_ip_geolocation_resolution():
    """Verify resolution of known adversary and major infrastructure IPs."""
    geo_de = geo_service.resolve_ip("185.220.101.44")
    assert geo_de is not None
    assert geo_de.country == "Germany"
    assert geo_de.city == "Frankfurt am Main"
    assert geo_de.is_tor is True
    assert geo_de.latitude != 0.0

    geo_ru = geo_service.resolve_ip("194.26.29.112")
    assert geo_ru is not None
    assert geo_ru.country == "Russia"
    assert geo_ru.is_hosting is True

def test_haversine_geodesic_distance():
    """Verify great-circle distance calculation between Frankfurt and Redmond (~8,200 km)."""
    # Frankfurt: 50.1109, 8.6821
    # Redmond: 47.6740, -122.1215
    dist = GeolocationService.calculate_haversine_distance(50.1109, 8.6821, 47.6740, -122.1215)
    assert 8000 <= dist <= 8500

    # Same location distance is 0
    assert GeolocationService.calculate_haversine_distance(50.1109, 8.6821, 50.1109, 8.6821) == 0.0

def test_build_relay_trajectory():
    """Verify chronological trajectory builder computes distance and origin attribution."""
    hops = [
        RelayHop(
            hop_number=1,
            ip="185.220.101.44",
            latitude=50.1109,
            longitude=8.6821,
            city="Frankfurt",
            country="Germany",
            isp="Zwiebelfreunde",
            asn="AS200651",
            delay_seconds=0,
            is_origin=True,
            is_tor=True
        ),
        RelayHop(
            hop_number=2,
            ip="40.107.22.85",
            latitude=47.6740,
            longitude=-122.1215,
            city="Redmond",
            country="United States",
            isp="Microsoft",
            asn="AS8075",
            delay_seconds=42,
            is_hosting=True
        )
    ]
    trajectory = geo_service.build_relay_trajectory(hops)
    assert trajectory["total_points"] == 2
    assert trajectory["origin_ip"] == "185.220.101.44"
    assert trajectory["has_tor"] is True
    assert trajectory["total_distance_km"] > 8000
    assert trajectory["total_delay_seconds"] == 42

def test_api_geo_lookup_endpoint():
    """Verify GET /api/v1/geo/lookup/{ip} returns geolocation metadata."""
    res = client.get("/api/v1/geo/lookup/185.220.101.44")
    assert res.status_code == 200
    data = res.json()
    assert data["country"] == "Germany"
    assert data["city"] == "Frankfurt am Main"
    assert data["is_tor"] is True

    # Private IP returns 404
    res_priv = client.get("/api/v1/geo/lookup/192.168.1.1")
    assert res_priv.status_code == 404

def test_api_geo_trajectory_endpoint():
    """Verify POST /api/v1/geo/trajectory returns geodesic trajectory."""
    hops_payload = [
        {
            "hop_number": 1,
            "ip": "185.220.101.44",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "city": "Frankfurt",
            "country": "Germany",
            "is_origin": True,
            "delay_seconds": 0
        },
        {
            "hop_number": 2,
            "ip": "40.107.22.85",
            "latitude": 47.6740,
            "longitude": -122.1215,
            "city": "Redmond",
            "country": "United States",
            "is_origin": False,
            "delay_seconds": 25
        }
    ]
    res = client.post("/api/v1/geo/trajectory", json=hops_payload)
    assert res.status_code == 200
    data = res.json()
    assert "trajectory" in data
    assert data["total_distance_km"] > 8000
    assert data["origin_ip"] == "185.220.101.44"

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
from starlette.testclient import TestClient
from backend.main import app
from backend.services.threat_intel_service import threat_intel_service
from backend.services.mitre_matrix_service import mitre_matrix_service

client = TestClient(app)

def test_threat_intel_ioc_lookup_ip():
    """Verifies IP IOC lookup with Geolocation, Tor detection, and MITRE mapping."""
    res = client.post("/api/v1/intel/lookup", json={"query": "185.220.101.44", "type": "ip"})
    assert res.status_code == 200
    data = res.json()
    assert data["query"] == "185.220.101.44"
    assert data["ioc_type"] == "IPv4 Address"
    assert data["reputation"] == "Malicious"
    assert data["threat_score"] >= 90
    assert data["geolocation"] is not None
    assert data["geolocation"]["is_tor"] is True
    assert any("T1090" in tech for tech in data["mitre_techniques"])
    assert data["blacklists_hit"] > 0

def test_threat_intel_ioc_lookup_domain_feed_match():
    """Verifies domain lookup matching OpenPhish feed and brand typosquatting."""
    res = client.post("/api/v1/intel/lookup", json={"query": "docuslgn-review.live", "type": "domain"})
    assert res.status_code == 200
    data = res.json()
    assert data["reputation"] == "Malicious"
    assert data["threat_score"] >= 85
    assert any("OpenPhish" in t for t in data["associated_threats"]) or any("Brand" in t for t in data["associated_threats"])
    assert any("T1566" in tech for tech in data["mitre_techniques"])

def test_threat_intel_ioc_lookup_hash():
    """Verifies SHA-256 payload lookup matching URLhaus malware dropper feed."""
    dropper_hash = "8f3e5b7298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b499"
    res = client.post("/api/v1/intel/lookup", json={"query": dropper_hash, "type": "hash"})
    assert res.status_code == 200
    data = res.json()
    assert data["reputation"] == "Malicious"
    assert data["threat_score"] >= 90
    assert any("URLhaus" in t for t in data["associated_threats"])
    assert data["blacklists_hit"] > 30

def test_threat_intel_feeds_status_and_sync():
    """Verifies feed synchronization telemetry and on-demand sync."""
    status_res = client.get("/api/v1/intel/feeds/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["total_indicators"] >= 10
    assert len(status_data["providers"]) >= 5
    assert any(p["name"] == "OpenPhish Feed" for p in status_data["providers"])

    # On-demand sync
    sync_res = client.post("/api/v1/intel/feeds/sync")
    assert sync_res.status_code == 200
    sync_data = sync_res.json()
    assert sync_data["total_indicators"] >= 10

def test_mitre_matrix_taxonomy_endpoint():
    """Verifies full MITRE ATT&CK Enterprise Matrix taxonomy."""
    res = client.get("/api/v1/mitre/matrix")
    assert res.status_code == 200
    data = res.json()
    assert data["total_tactics"] >= 8
    assert data["total_techniques"] >= 20
    tactic_names = [t["name"] for t in data["tactics"]]
    assert "Initial Access" in tactic_names
    assert "Defense Evasion" in tactic_names
    assert "Credential Access" in tactic_names
    assert "Command and Control" in tactic_names

def test_mitre_heatmap_aggregation_endpoint():
    """Verifies telemetry heatmap aggregation mapped from active cases."""
    res = client.get("/api/v1/mitre/heatmap")
    assert res.status_code == 200
    data = res.json()
    assert data["total_detections"] > 0
    assert "T1566.002" in data["hits"] or "T1090.003" in data["hits"] or "T1657" in data["hits"]
    # Check hit properties
    hit = next(iter(data["hits"].values()))
    assert hit["detection_count"] > 0
    assert len(hit["case_ids"]) > 0
    assert hit["severity"] in ["critical", "high", "medium", "low"]

def test_mitre_export_navigator_layer():
    """Verifies exportable MITRE ATT&CK Navigator JSON schema compliance."""
    res = client.get("/api/v1/mitre/export-layer")
    assert res.status_code == 200
    layer = res.json()
    assert layer["domain"] == "enterprise-attack"
    assert "techniques" in layer
    assert len(layer["techniques"]) > 0
    tech = layer["techniques"][0]
    assert "techniqueID" in tech
    assert "color" in tech
    assert "score" in tech

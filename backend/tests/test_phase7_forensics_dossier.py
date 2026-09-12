import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app
from backend.services.case_store import case_store
from backend.services.forensic_dossier_service import forensic_dossier_service

client = TestClient(app)

def test_forensic_dossier_generation():
    """Verifies that the full forensic dossier is generated with all expected evidence fields."""
    response = client.get("/api/v1/forensics/dossier/CASE-2026-0891")
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["case_id"] == "CASE-2026-0891"
    assert data["threat_score"] == 94
    assert data["severity"] == "critical"
    assert data["verdict"] == "MALICIOUS"
    assert len(data["primary_sha256"]) == 64
    assert len(data["md5_digest"]) == 32
    assert len(data["sha1_digest"]) == 40
    assert len(data["chain_of_custody"]) == 6
    assert len(data["relay_hops"]) >= 1
    assert len(data["defense_recommendations"]) >= 3

def test_chain_of_custody_validity():
    """Verifies that the sequential SHA-256 Merkle chain passes cryptographic verification."""
    response = client.post("/api/v1/forensics/verify-chain/CASE-2026-0891")
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["is_valid"] is True
    assert data["tamper_detected"] is False
    assert data["chain_length"] == 6
    assert len(data["genesis_hash"]) == 64
    assert len(data["latest_block_hash"]) == 64
    for b in data["block_details"]:
        assert b["hash_matches"] is True
        assert b["link_valid"] is True

def test_chain_of_custody_tamper_detection():
    """Verifies that altering an artifact hash or action in any block triggers tamper detection."""
    case = case_store.get_case("CASE-2026-0891")
    assert case is not None

    blocks = forensic_dossier_service.generate_chain_of_custody(case)
    assert len(blocks) == 6

    # Normal chain should be valid
    normal_verif = forensic_dossier_service.verify_chain_of_custody(blocks)
    assert normal_verif.is_valid is True
    assert normal_verif.tamper_detected is False

    # Simulate adversary tampering with Block 2 (Artifact hash changed)
    tampered_blocks = [b.model_copy() for b in blocks]
    tampered_blocks[2].artifact_hash = "deadbeef" * 8

    tampered_verif = forensic_dossier_service.verify_chain_of_custody(tampered_blocks)
    assert tampered_verif.is_valid is False
    assert tampered_verif.tamper_detected is True
    assert tampered_verif.block_details[2]["hash_matches"] is False

def test_stix_2_1_bundle_export():
    """Verifies that case threat intelligence is exported in OASIS STIX 2.1 format."""
    response = client.get("/api/v1/forensics/export/stix/CASE-2026-0891")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "threat-actor" in types
    assert "indicator" in types
    assert "report" in types

def test_ioc_csv_export():
    """Verifies that IOCs are exported as a structured CSV."""
    response = client.get("/api/v1/forensics/export/csv/CASE-2026-0891")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    
    csv_text = response.text
    assert "Indicator,Type,Threat_Severity,Source_Case,First_Seen" in csv_text
    assert "185.220.101.44" in csv_text
    assert "corporate-accts-wire.com" in csv_text

def test_defensive_rules_generation():
    """Verifies automated generation of Suricata, Snort, and YARA defensive rules."""
    response = client.get("/api/v1/forensics/export/rules/CASE-2026-0891")
    assert response.status_code == 200
    data = response.json()

    assert data["case_id"] == "CASE-2026-0891"
    assert data["ioc_count"] >= 3
    assert "alert dns" in data["suricata_rules"]
    assert "alert ip" in data["suricata_rules"]
    assert "alert tcp" in data["snort_rules"]
    assert "rule PhishGuard_Phishing_Lure_" in data["yara_rule"]
    assert "$subject =" in data["yara_rule"]

def test_html_dossier_export():
    """Verifies that the standalone HTML report is generated."""
    response = client.get("/api/v1/forensics/export/html/CASE-2026-0891")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PHISHGUARD AI FORENSIC INCIDENT DOSSIER" in response.text
    assert "CASE-2026-0891" in response.text
    assert "OFFICIAL FORENSIC SEAL" in response.text

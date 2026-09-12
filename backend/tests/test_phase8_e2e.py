import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app
from backend.services.case_store import case_store
from backend.services.forensic_dossier_service import forensic_dossier_service
from backend.data.sample_emails import SAMPLE_EMAILS

client = TestClient(app)

def test_e2e_system_diagnostics_all_subsystems_healthy():
    """
    Phase 8 E2E Test 1:
    Verifies that the system diagnostics audit confirms all 8 core subsystems
    are fully initialized, operational, and reporting HEALTHY status.
    """
    response = client.get("/api/v1/system/diagnostics")
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["overall_status"] == "HEALTHY"
    assert data["subsystems_operational"] == 8
    assert data["total_subsystems"] == 8
    
    subsystem_ids = [s["id"] for s in data["subsystems"]]
    expected_ids = [
        "mime_parser",
        "geoip_tracer",
        "ml_classifier",
        "nemotron_llm",
        "case_store",
        "threat_graph",
        "cti_mitre",
        "merkle_forensics"
    ]
    for eid in expected_ids:
        assert eid in subsystem_ids
        sub = next(s for s in data["subsystems"] if s["id"] == eid)
        assert sub["status"] == "OPERATIONAL"

def test_e2e_full_lifecycle_pipeline():
    """
    Phase 8 E2E Test 2:
    Validates the entire end-to-end operational lifecycle:
      Ingestion -> Header Forensics -> Geo Trajectory -> 97.55% ML Inference ->
      Case Store Promotion -> Threat Graph Correlation -> CTI Feed & MITRE ->
      Merkle Chain of Custody -> Tamper Detection -> Multi-Format Exports.
    """
    sample_bec = next(s for s in SAMPLE_EMAILS if s["id"] == "sample-bec")
    raw_payload = sample_bec["raw_text"]

    # 1. Ingest and Analyze Raw RFC 822 Email
    analyze_res = client.post("/api/v1/analyze/raw", json={"raw_text": raw_payload})
    assert analyze_res.status_code == 200, analyze_res.text
    analysis = analyze_res.json()

    # Verify Header Forensics & Authentication Matrix
    assert "headers" in analysis
    headers = analysis["headers"]
    assert "corporate-accts-wire.com" in headers["from_address"]
    assert headers["spf_result"] == "fail"
    assert headers["dmarc_result"] == "fail"
    assert headers["alignment_from_replyto"] is False

    # Verify Relay Hops & Geo Trajectory
    assert "hops" in analysis
    assert len(analysis["hops"]) >= 1
    origin_hop = next((h for h in analysis["hops"] if h.get("is_origin")), analysis["hops"][0])
    assert origin_hop["ip"] == "185.220.101.44"
    assert origin_hop["country"] != ""

    # Verify Dual AI Engine Scoring (ML + Hybrid)
    assert "ml_prediction" in analysis
    assert analysis["ml_prediction"]["is_trained"] is True
    assert analysis["ml_prediction"]["phishing_probability"] > 0.50
    assert analysis["threat_score"]["score"] >= 80
    assert analysis["threat_score"]["verdict"] in ["Malicious", "Suspicious"]

    # 2. Promote Analyzed Incident to Active Case Store
    promote_payload = {
        "analysis_id": "ANALYSIS-E2E-BEC-001",
        "subject": analysis["subject"],
        "sender": analysis["sender"],
        "recipient": analysis["recipient"],
        "earliest_ip": origin_hop["ip"],
        "origin_country": origin_hop.get("country", "Germany"),
        "threat_score": analysis["threat_score"]["score"],
        "severity": analysis["threat_score"]["severity"],
        "summary": "E2E Automated BEC Investigation",
        "sha256_hash": analysis.get("evidence_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "sender_domain": "corporate-accts-wire.com",
        "threat_indicators": [ind["title"] for ind in analysis.get("indicators", [])],
        "extracted_urls": [u["url"] for u in analysis.get("extracted_urls", [])],
        "assigned_analyst": "Alex Vance (Lead)"
    }
    promote_res = client.post("/api/v1/investigations/promote", json=promote_payload)
    assert promote_res.status_code == 200, promote_res.text
    promoted_case = promote_res.json()
    case_id = promoted_case["case_id"]
    assert case_id.startswith("CASE-")

    # Verify Case Persisted
    case_fetch = client.get(f"/api/v1/investigations/{case_id}")
    assert case_fetch.status_code == 200
    assert case_fetch.json()["case_id"] == case_id

    # 3. Verify Case Presence in Threat Correlation Graph
    graph_res = client.get("/api/v1/investigations/correlation-graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert any(node["id"] == case_id for node in graph_data["nodes"])
    assert any(node["id"] == f"ip:{origin_hop['ip']}" for node in graph_data["nodes"])

    # 4. Verify Threat Intelligence Feed & MITRE ATT&CK Mapping
    intel_res = client.get("/api/v1/intel/feeds/status")
    assert intel_res.status_code == 200
    mitre_res = client.get("/api/v1/mitre/matrix")
    assert mitre_res.status_code == 200
    mitre_data = mitre_res.json()
    assert len(mitre_data["tactics"]) >= 8

    # 5. Generate NIST SP 800-86 Cryptographic Forensic Dossier
    dossier_res = client.get(f"/api/v1/forensics/dossier/{case_id}")
    assert dossier_res.status_code == 200, dossier_res.text
    dossier = dossier_res.json()
    assert dossier["case_id"] == case_id
    assert len(dossier["primary_sha256"]) == 64
    assert len(dossier["chain_of_custody"]) == 6

    # 6. Verify Sequential Cryptographic Merkle Chain
    verify_res = client.post(f"/api/v1/forensics/verify-chain/{case_id}")
    assert verify_res.status_code == 200
    chain_status = verify_res.json()
    assert chain_status["is_valid"] is True
    assert chain_status["tamper_detected"] is False
    assert chain_status["chain_length"] == 6

    # 7. Verify Multi-Format Exporters
    # STIX 2.1 CTI
    stix_res = client.get(f"/api/v1/forensics/export/stix/{case_id}")
    assert stix_res.status_code == 200
    assert stix_res.json()["type"] == "bundle"

    # CSV IOC
    csv_res = client.get(f"/api/v1/forensics/export/csv/{case_id}")
    assert csv_res.status_code == 200
    assert "Indicator,Type,Threat_Severity" in csv_res.text

    # Defensive Rules (Suricata, Snort, YARA)
    rules_res = client.get(f"/api/v1/forensics/export/rules/{case_id}")
    assert rules_res.status_code == 200
    rules_data = rules_res.json()
    assert "alert" in rules_data["suricata_rules"]
    assert "rule PhishGuard_" in rules_data["yara_rule"]

    # Standalone HTML Dossier
    html_res = client.get(f"/api/v1/forensics/export/html/{case_id}")
    assert html_res.status_code == 200
    assert "PHISHGUARD AI FORENSIC INCIDENT DOSSIER" in html_res.text
    assert "OFFICIAL FORENSIC SEAL" in html_res.text

def test_e2e_scenario_1_bec_wire_transfer():
    """
    Phase 8 E2E Test 3: Benchmark Scenario 1 - Executive BEC Wire Transfer.
    Simulates spoofed executive payment redirection via Tor relay.
    """
    bec_sample = next(s for s in SAMPLE_EMAILS if s["id"] == "sample-bec")
    res = client.post("/api/v1/analyze/raw", json={"raw_text": bec_sample["raw_text"]})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"]["score"] >= 88
    assert data["threat_score"]["severity"] == "critical"
    assert data["headers"]["spf_result"] == "fail"
    assert data["headers"]["alignment_from_replyto"] is False
    assert any("wire" in ind["title"].lower() or "financial" in ind["title"].lower() or "transfer" in ind["title"].lower() or "spf" in ind["title"].lower() for ind in data["indicators"])

def test_e2e_scenario_2_credential_harvesting_homoglyph():
    """
    Phase 8 E2E Test 4: Benchmark Scenario 2 - Microsoft 365 Credential Harvester.
    Simulates typosquatting homoglyph domain ('rnicrosoft') with fake SSO login lure.
    """
    m365_sample = next(s for s in SAMPLE_EMAILS if s["id"] == "sample-m365")
    res = client.post("/api/v1/analyze/raw", json={"raw_text": m365_sample["raw_text"]})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"]["score"] >= 80
    assert data["threat_score"]["severity"] == "critical"
    assert any("rnicrosoft" in u["url"] for u in data["extracted_urls"])
    assert any("lookalike" in ind["title"].lower() or "credential" in ind["title"].lower() or "suspicious" in ind["title"].lower() for ind in data["indicators"])

def test_e2e_scenario_3_malware_dropper():
    """
    Phase 8 E2E Test 5: Benchmark Scenario 3 - Delivery Exception Malware Dropper.
    Simulates DHL delivery notice with direct raw IP destination URL.
    """
    dhl_sample = next(s for s in SAMPLE_EMAILS if s["id"] == "sample-dhl")
    res = client.post("/api/v1/analyze/raw", json={"raw_text": dhl_sample["raw_text"]})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"]["score"] >= 75
    assert data["threat_score"]["severity"] in ["critical", "high"]
    assert any("185.220.101.5" in u["url"] for u in data["extracted_urls"])

def test_e2e_scenario_4_benign_corporate_communication():
    """
    Phase 8 E2E Test 6: Benchmark Scenario 4 - Verified Corporate Internal Briefing.
    Simulates legitimate internal email with valid SPF/DKIM/DMARC alignment.
    Must produce zero false positives and score <= 20 (Low / Benign).
    """
    benign_sample = next(s for s in SAMPLE_EMAILS if s["id"] == "sample-benign")
    res = client.post("/api/v1/analyze/raw", json={"raw_text": benign_sample["raw_text"]})
    assert res.status_code == 200
    data = res.json()

    assert data["threat_score"]["score"] <= 20
    assert data["threat_score"]["severity"] == "low"
    assert data["threat_score"]["verdict"] == "Benign"
    assert data["headers"]["spf_result"] == "pass"
    assert data["headers"]["dkim_result"] == "pass"
    assert data["headers"]["dmarc_result"] == "pass"

def test_e2e_tamper_detection_resilience():
    """
    Phase 8 E2E Test 7: Cryptographic Tamper Detection & Merkle Seal Resilience.
    Verifies that altering any block in the SHA-256 custody ledger immediately
    invalidates the cryptographic chain and triggers tamper alerts.
    """
    case = case_store.get_case("CASE-2026-0891")
    assert case is not None

    blocks = forensic_dossier_service.generate_chain_of_custody(case)
    assert len(blocks) == 6

    # Normal chain is valid
    initial_verif = forensic_dossier_service.verify_chain_of_custody(blocks)
    assert initial_verif.is_valid is True
    assert initial_verif.tamper_detected is False

    # Simulate adversarial tampering: Modifying Block 3's action_summary and hash
    tampered_blocks = [b.model_copy() for b in blocks]
    tampered_blocks[3].action_summary = "MALICIOUSLY_ALTERED_CONTAINMENT"
    tampered_blocks[3].artifact_hash = "ffffffff" * 8

    tampered_verif = forensic_dossier_service.verify_chain_of_custody(tampered_blocks)
    assert tampered_verif.is_valid is False
    assert tampered_verif.tamper_detected is True
    assert tampered_verif.block_details[3]["hash_matches"] is False

def test_e2e_api_resilience_and_validation():
    """
    Phase 8 E2E Test 8: API Robustness and Error Boundary Verification.
    Verifies that malformed inputs and nonexistent case lookups return appropriate
    HTTP client error codes without crashing the backend service.
    """
    # Nonexistent case lookup
    missing_case_res = client.get("/api/v1/forensics/dossier/CASE-DOES-NOT-EXIST")
    assert missing_case_res.status_code == 404

    # Nonexistent case chain verification
    missing_chain_res = client.post("/api/v1/forensics/verify-chain/CASE-DOES-NOT-EXIST")
    assert missing_chain_res.status_code == 404

    # Empty payload to analyze endpoint
    empty_res = client.post("/api/v1/analyze/raw", json={})
    assert empty_res.status_code == 422

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "PhishGuard AI" in data["message"]

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["soc_defenses"] == "active"

def test_dashboard_stats():
    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_analyzed"] > 0
    assert data["threats_detected"] > 0
    assert data["high_risk_count"] > 0
    assert "critical" in data["severity_distribution"]
    assert len(data["recent_activity"]) > 0

def test_investigations_list_and_filter():
    # List all
    res = client.get("/api/v1/investigations")
    assert res.status_code == 200
    cases = res.json()
    assert len(cases) > 0

    # Filter by severity critical
    res_crit = client.get("/api/v1/investigations?severity=critical")
    assert res_crit.status_code == 200
    crit_cases = res_crit.json()
    for c in crit_cases:
        assert c["severity"] == "critical"

    # Search filter
    res_search = client.get("/api/v1/investigations?search=Microsoft")
    assert res_search.status_code == 200
    search_cases = res_search.json()
    assert len(search_cases) >= 1
    assert "Microsoft" in search_cases[0]["subject"]

def test_update_case_status():
    res = client.get("/api/v1/investigations")
    case_id = res.json()[0]["case_id"]
    
    update_res = client.patch(
        f"/api/v1/investigations/{case_id}/status",
        json={"status": "Quarantined", "notes": "Automated Phase 1 test quarantine"}
    )
    assert update_res.status_code == 200
    updated = update_res.json()
    assert updated["status"] == "Quarantined"

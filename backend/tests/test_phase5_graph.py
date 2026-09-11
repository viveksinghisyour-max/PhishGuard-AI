import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.case_store import case_store
from backend.services.threat_graph_service import threat_graph_service
from backend.models.schemas import PromoteAnalysisRequest

client = TestClient(app)

def test_threat_correlation_graph_generation():
    graph = threat_graph_service.build_global_correlation_graph()
    assert graph is not None
    assert len(graph.nodes) > 0
    assert len(graph.links) > 0
    
    # Check node types
    node_types = {n.type for n in graph.nodes}
    assert "case" in node_types
    assert "ip" in node_types
    assert "domain" in node_types
    assert "mailbox" in node_types

    # Check cross-case correlation detection
    cross_case_links = [l for l in graph.links if l.is_cross_case]
    assert len(cross_case_links) > 0
    assert any("Shared" in (l.label or "") or "Co-Located" in (l.label or "") for l in cross_case_links)

def test_case_subgraph_extraction():
    subgraph = threat_graph_service.build_case_subgraph("CASE-2026-0891")
    assert subgraph is not None
    assert len(subgraph.nodes) > 0
    assert any(n.id == "CASE-2026-0891" for n in subgraph.nodes)
    assert subgraph.summary.get("focus_case") == "CASE-2026-0891"

def test_case_notes_addition():
    note = case_store.add_note(
        case_id="CASE-2026-0891",
        author="Sarah Chen",
        text="Correlated attack pattern with APT29 phishing playbook."
    )
    assert note is not None
    assert note.author == "Sarah Chen"
    assert "Correlated" in note.text

    case = case_store.get_case("CASE-2026-0891")
    assert len(case.notes) > 0
    assert case.notes[0].text == "Correlated attack pattern with APT29 phishing playbook."

def test_containment_action_execution():
    action = case_store.execute_containment(
        case_id="CASE-2026-0889",
        action_type="block_ip",
        target="194.26.29.112",
        executed_by="Alex Vance (Lead)",
        details="Added IP to perimeter edge firewall drop list."
    )
    assert action is not None
    assert action.action_type == "block_ip"
    assert action.status == "Executed"

    case = case_store.get_case("CASE-2026-0889")
    assert len(case.containment_actions) > 0
    assert case.containment_actions[0].target == "194.26.29.112"

def test_promote_analysis_to_case():
    payload = PromoteAnalysisRequest(
        analysis_id="ANALYSIS-TEST-9999",
        subject="Suspicious Invoice Payment Verification",
        sender="billing@fraudulent-supplier.com",
        recipient="accounts-payable@enterprise.com",
        earliest_ip="103.235.46.39",
        origin_country="Hong Kong",
        threat_score=85,
        severity="critical",
        summary="Automated promotion test case",
        sha256_hash="d41d8cd98f00b204e9800998ecf8427e",
        sender_domain="fraudulent-supplier.com",
        threat_indicators=["Typosquatted Supplier", "High Velocity Ingestion"],
        extracted_urls=["https://fraudulent-supplier.com/pay.php"]
    )
    new_case = case_store.promote_analysis_to_case(payload)
    assert new_case is not None
    assert new_case.case_id.startswith("CASE-2026-")
    assert new_case.sender == "billing@fraudulent-supplier.com"
    assert len(new_case.notes) == 1

def test_api_investigations_phase5_endpoints():
    # 1. Global graph endpoint
    res_graph = client.get("/api/v1/investigations/correlation-graph")
    assert res_graph.status_code == 200
    data_graph = res_graph.json()
    assert "nodes" in data_graph
    assert "links" in data_graph
    assert "summary" in data_graph

    # 2. Case subgraph endpoint
    res_sub = client.get("/api/v1/investigations/CASE-2026-0891/graph")
    assert res_sub.status_code == 200
    assert len(res_sub.json()["nodes"]) > 0

    # 3. Add note endpoint
    res_note = client.post(
        "/api/v1/investigations/CASE-2026-0891/notes",
        json={"author": "Marcus Brody", "text": "DNS records updated."}
    )
    assert res_note.status_code == 200
    assert res_note.json()["author"] == "Marcus Brody"

    # 4. Containment endpoint
    res_act = client.post(
        "/api/v1/investigations/CASE-2026-0891/containment",
        json={
            "action_type": "quarantine_inbox",
            "target": "finance-dept@enterprise.com",
            "executed_by": "Alex Vance (Lead)",
            "details": "Triggered automated mailbox isolation"
        }
    )
    assert res_act.status_code == 200
    assert res_act.json()["action_type"] == "quarantine_inbox"

    # 5. Analyst update endpoint
    res_analyst = client.patch(
        "/api/v1/investigations/CASE-2026-0891/analyst",
        json={"assigned_analyst": "Sarah Chen"}
    )
    assert res_analyst.status_code == 200
    assert res_analyst.json()["assigned_analyst"] == "Sarah Chen"

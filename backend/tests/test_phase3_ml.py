import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_ml_status_endpoint():
    """Verify ML status returns trained model metadata, accuracy, and dataset breakdown."""
    response = client.get("/api/v1/ml/status")
    assert response.status_code == 200
    data = response.json()
    assert data["is_trained"] is True
    assert data["accuracy"] > 0.85
    assert data["f1_score"] > 0.85
    assert "confusion_matrix" in data
    assert "top_phishing_tokens" in data
    assert len(data["top_phishing_tokens"]) > 0
    assert "dataset_breakdown" in data
    assert len(data["dataset_breakdown"]) > 0

def test_ml_datasets_endpoint():
    """Verify ML datasets endpoint enumerates all uploaded CSV datasets."""
    response = client.get("/api/v1/ml/datasets")
    assert response.status_code == 200
    data = response.json()
    assert data["total_count"] >= 8
    names = [d["name"] for d in data["datasets"]]
    assert "phishing_email.csv" in names
    assert "CEAS_08.csv" in names
    assert "StealthPhisher2025.csv" in names

def test_ml_predict_phishing_and_ham():
    """Verify live text inference on phishing vs benign samples."""
    # Phishing prompt
    phish_res = client.post("/api/v1/ml/predict", json={
        "text": "URGENT ACTION REQUIRED: Wire transfer payment invoice overdue $95,000. Send to foreign escrow account immediately."
    })
    assert phish_res.status_code == 200
    p_data = phish_res.json()
    assert p_data["is_phishing"] is True
    assert p_data["phishing_probability"] >= 0.60
    assert len(p_data["contributing_tokens"]) > 0

    # Ham prompt
    ham_res = client.post("/api/v1/ml/predict", json={
        "text": "Hi team, please find attached the quarterly engineering sprint notes and lunch menu for our Friday review."
    })
    assert ham_res.status_code == 200
    h_data = ham_res.json()
    assert h_data["phishing_probability"] < 0.50

def test_analyze_email_includes_ml_prediction():
    """Verify email analysis pipeline populates ml_prediction and hybrid scoring."""
    sample_raw = """From: executive@external-scam.xyz
To: victim@company.com
Subject: URGENT: Wire Transfer Authorization Required Immediately
Date: Fri, 11 Sep 2026 10:00:00 +0000
Received: from mail.external-scam.xyz ([185.220.101.44]) by mx.google.com with ESMTP; Fri, 11 Sep 2026 10:00:00 +0000
Received-SPF: fail (google.com: domain of executive@external-scam.xyz does not designate 185.220.101.44 as permitted sender)
Authentication-Results: mx.google.com; dkim=none; dmarc=fail

Please process immediate wire transfer of $85,000 to new account details before 5 PM today.
"""
    response = client.post("/api/v1/analyze/raw", json={"raw_text": sample_raw})
    assert response.status_code == 200
    data = response.json()
    assert "ml_prediction" in data
    assert data["ml_prediction"] is not None
    assert data["ml_prediction"]["is_trained"] is True
    assert data["ml_prediction"]["phishing_probability"] > 0.50
    assert data["threat_score"]["score"] >= 70

def test_deep_reasoning_endpoint():
    """Verify deep reasoning endpoint returns structured SOC reasoning and playbook."""
    payload = {
        "subject": "Wire Transfer Fraud Attempt",
        "sender": "attacker@spoofed.com",
        "recipient": "finance@company.com",
        "headers": {
            "spf_result": "fail",
            "dmarc_result": "fail"
        },
        "hops": [],
        "extracted_urls": [{"url": "http://185.220.101.44/login"}],
        "attachments": [],
        "threat_score": {"score": 88, "verdict": "Malicious"},
        "ml_prediction": {"phishing_probability": 0.89, "contributing_tokens": [{"token": "wire"}]},
        "body_text": "Please initiate urgent wire transfer to bank account."
    }
    response = client.post("/api/v1/analyze/deep-reasoning", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "reasoning" in data
    assert "analysis" in data
    assert len(data["analysis"]) > 100

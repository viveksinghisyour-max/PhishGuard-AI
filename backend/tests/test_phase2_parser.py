import io
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.email_parser import EmailParserService
from backend.services.header_forensics import HeaderForensicsService
from backend.services.ai_threat_engine import AIThreatEngine
from backend.data.sample_emails import SAMPLE_EMAILS

client = TestClient(app)

def test_email_parser_multipart_and_urls():
    raw_email = """From: "Security Team" <security@example.com>
To: target@phishguardai.com
Subject: Test Suspicious Email
Date: Wed, 09 Sep 2026 12:00:00 +0000
Message-ID: <msg-12345@example.com>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html>
<body>
  <p>Please review invoice at <a href="http://192.168.1.50/login.php">IP Portal</a>.</p>
  <p>Also visit our partner at <a href="https://login.rnicrosoft-sec-auth.top/auth">M365 Portal</a>.</p>
</body>
</html>"""

    parsed = EmailParserService.parse_raw_message(raw_email)
    assert parsed["subject"] == "Test Suspicious Email"
    assert "security@example.com" in parsed["from_header"]
    assert len(parsed["extracted_urls"]) >= 2
    assert parsed["sha256_hash"] is not None

    ip_urls = [u for u in parsed["extracted_urls"] if u.is_ip_based]
    assert len(ip_urls) == 1
    assert "192.168.1.50" in ip_urls[0].url


def test_header_forensics_authentication_matrix():
    raw_email = """Received: from mail.attacker.xyz (185.220.101.5) by mx.phishguardai.com with ESMTP id 1234; Wed, 09 Sep 2026 12:00:00 +0000
Authentication-Results: mx.phishguardai.com; spf=fail smtp.mailfrom=bounce@evil.com; dkim=fail; dmarc=fail action=reject
From: "PhishGuard CEO" <ceo@evil.com>
To: cfo@phishguardai.com
Reply-To: offsite-payouts@hidden.net
Return-Path: <bounce@evil.com>
Subject: Urgent wire transfer request
Date: Wed, 09 Sep 2026 12:00:00 +0000

Urgent wire transfer of $50,000 required immediately."""

    parsed = EmailParserService.parse_raw_message(raw_email)
    headers = HeaderForensicsService.analyze_headers(parsed)

    assert headers.spf_result == "fail"
    assert headers.dkim_result == "fail"
    assert headers.dmarc_result == "fail"
    assert headers.alignment_from_replyto is False

    hops, earliest_ip, origin_geo = HeaderForensicsService.parse_relay_hops(parsed)
    assert len(hops) >= 1
    assert earliest_ip == "185.220.101.5"
    assert origin_geo is not None
    assert origin_geo.country == "Germany"
    assert origin_geo.is_tor is True


def test_ai_threat_scoring_engine():
    raw_email = SAMPLE_EMAILS[0]["raw_text"]  # BEC sample
    parsed = EmailParserService.parse_raw_message(raw_email)
    headers = HeaderForensicsService.analyze_headers(parsed)
    hops, earliest_ip, _ = HeaderForensicsService.parse_relay_hops(parsed)

    score, indicators, summary, recs = AIThreatEngine.evaluate(
        headers=headers,
        body_text=parsed["body_text"],
        urls=parsed["extracted_urls"],
        attachments=parsed["attachments"],
        hops=hops,
        earliest_origin_ip=earliest_ip or "Unknown"
    )

    assert score.score >= 76
    assert score.severity == "critical"
    assert score.verdict == "Malicious"
    assert len(indicators) > 0
    assert any("wire" in ind.title.lower() or "financial" in ind.title.lower() for ind in indicators)
    assert len(recs) > 0


def test_api_analyze_samples():
    response = client.get("/api/v1/analyze/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 4
    assert any(s["id"] == "sample-bec" for s in samples)


def test_api_analyze_raw():
    raw_email = SAMPLE_EMAILS[0]["raw_text"]
    response = client.post("/api/v1/analyze/raw", json={"raw_text": raw_email})
    assert response.status_code == 200
    data = response.json()

    assert data["threat_score"]["score"] >= 76
    assert data["headers"]["spf_result"] == "fail"
    assert data["earliest_origin_ip"] == "185.220.101.44"
    assert data["origin_geo"]["country"] == "Germany"
    assert len(data["indicators"]) > 0


def test_api_analyze_file_upload():
    raw_email = SAMPLE_EMAILS[1]["raw_text"].encode("utf-8")
    file_payload = {"file": ("test_m365.eml", io.BytesIO(raw_email), "message/rfc822")}
    
    response = client.post("/api/v1/analyze/file", files=file_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["threat_score"]["score"] >= 76
    assert data["headers"]["dmarc_result"] == "fail"
    assert "rnicrosoft-security-portal.xyz" in data["sender"]

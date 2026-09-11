import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, UploadFile, File, HTTPException, Body
from backend.models.schemas import (
    EmailSubmissionRequest,
    AnalysisResult,
    InvestigationCase
)
from backend.services.email_parser import EmailParserService
from backend.services.header_forensics import HeaderForensicsService
from backend.services.ai_threat_engine import AIThreatEngine
from backend.services.case_store import case_store
from backend.data.sample_emails import SAMPLE_EMAILS
from backend.ml.predictor import predictor
from backend.services.llm_engine import llm_service

router = APIRouter(prefix="/analyze", tags=["analyze"])

def _process_analysis(raw_text: str, filename: str | None = None) -> AnalysisResult:
    """Executes the full forensic analysis pipeline on raw RFC 822 email text."""
    if not raw_text or not raw_text.strip():
        raise HTTPException(status_code=400, detail="Empty email payload provided")

    # 1. Parse MIME & RFC 822 content
    parsed = EmailParserService.parse_raw_message(raw_text, filename)

    # 2. Forensic Header Validation (SPF, DKIM, DMARC, Alignment)
    header_analysis = HeaderForensicsService.analyze_headers(parsed)

    # 3. SMTP Hop Traversal & Earliest Origin IP
    hops, earliest_ip, origin_geo = HeaderForensicsService.parse_relay_hops(parsed)

    # 4. Machine Learning NLP Inference on Unified Model
    combined_content = f"{parsed['subject']} {parsed['body_text']}".strip()
    ml_prediction = predictor.predict(combined_content)

    # 5. Hybrid Heuristic + Machine Learning Threat Scoring
    threat_score, indicators, summary, recs = AIThreatEngine.evaluate(
        headers=header_analysis,
        body_text=parsed["body_text"],
        urls=parsed["extracted_urls"],
        attachments=parsed["attachments"],
        hops=hops,
        earliest_origin_ip=earliest_ip or "Unknown",
        ml_prediction=ml_prediction
    )

    result_id = f"ANALYSIS-{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # 6. Persist as an Investigation Case for SOC Analysts
    case_item = InvestigationCase(
        case_id=f"CASE-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}",
        created_at=now_iso,
        subject=parsed["subject"],
        sender=header_analysis.from_address or parsed["from_header"],
        recipient=header_analysis.to_address or parsed["to_header"],
        earliest_ip=earliest_ip or "127.0.0.1",
        origin_country=origin_geo.country if origin_geo else "Unknown",
        threat_score=threat_score.score,
        severity=threat_score.severity,
        status="Quarantined" if threat_score.score >= 76 else ("Under Investigation" if threat_score.score >= 51 else "Open"),
        assigned_analyst="SOC Analyst 1",
        sha256_hash=parsed["sha256_hash"],
        summary=summary
    )
    case_store.add_case(case_item)

    return AnalysisResult(
        id=result_id,
        timestamp=now_iso,
        sha256_hash=parsed["sha256_hash"],
        header_fingerprint=parsed["header_fingerprint"],
        subject=parsed["subject"],
        sender=parsed["from_header"],
        recipient=parsed["to_header"],
        body_text=parsed["body_text"],
        body_html=parsed["body_html"],
        headers=header_analysis,
        hops=hops,
        earliest_origin_ip=earliest_ip,
        origin_geo=origin_geo,
        threat_score=threat_score,
        indicators=indicators,
        extracted_urls=parsed["extracted_urls"],
        attachments=parsed["attachments"],
        ml_prediction=ml_prediction,
        ai_summary=summary,
        recommended_actions=recs
    )


@router.post("/raw", response_model=AnalysisResult)
def analyze_raw_email(req: EmailSubmissionRequest):
    """Parses and evaluates a raw RFC 822 email string."""
    return _process_analysis(req.raw_text, req.filename)


@router.post("/file", response_model=AnalysisResult)
async def analyze_email_file(file: UploadFile = File(...)):
    """Uploads and analyzes a raw .EML or .MSG file."""
    content_bytes = await file.read()
    raw_text = content_bytes.decode('utf-8', errors='replace')
    return _process_analysis(raw_text, file.filename)


@router.get("/samples")
def get_sample_scenarios():
    """Returns preset benchmark RFC 822 email scenarios for 1-click testing."""
    return SAMPLE_EMAILS


@router.post("/deep-reasoning")
def get_deep_reasoning(email_data: Dict[str, Any] = Body(...)):
    """
    Executes deep NVIDIA Nemotron 550B reasoning on the provided analysis result.
    Returns reasoning thoughts trace, SOC attribution, and incident response playbook.
    """
    reasoning_report = llm_service.analyze_threat(email_data)
    return reasoning_report

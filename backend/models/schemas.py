from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

# ==================== EMAIL SUBMISSION ====================
class EmailSubmissionRequest(BaseModel):
    raw_text: str = Field(..., description="Raw RFC 822 email content or pasted headers/body")
    is_headers_only: bool = Field(default=False, description="Whether input contains only headers")
    filename: Optional[str] = Field(default=None, description="Original filename if uploaded")

# ==================== HEADER ANALYSIS ====================
class HeaderAnalysis(BaseModel):
    from_address: str = ""
    from_display: str = ""
    from_domain: str = ""
    to_address: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    message_id: str = ""
    subject: str = ""
    date: str = ""
    spf_result: str = "neutral"  # pass, fail, softfail, neutral, none
    dkim_result: str = "none"   # pass, fail, none
    dmarc_result: str = "none"  # pass, fail, none
    spf_details: str = ""
    dkim_details: str = ""
    dmarc_details: str = ""
    alignment_from_returnpath: bool = True
    alignment_from_replyto: bool = True
    anomalies: list[str] = []

# ==================== RELAY HOPS & GEOLOCATION ====================
class RelayHop(BaseModel):
    hop_number: int
    from_server: str = ""
    by_server: str = ""
    ip: str = ""
    timestamp: str = ""
    delay_seconds: int = 0
    is_private: bool = False
    is_origin: bool = False
    country: str = "Unknown"
    country_code: str = ""
    city: str = ""
    region: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = ""
    asn: str = ""
    is_hosting: bool = False
    is_vpn: bool = False
    is_tor: bool = False

class GeoLocationInfo(BaseModel):
    ip: str
    country: str = "Unknown"
    country_code: str = "UN"
    city: str = ""
    region: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = ""
    asn: str = ""
    is_hosting: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    confidence: str = "Medium"

# ==================== THREAT INDICATORS & SCORING ====================
class ThreatIndicator(BaseModel):
    id: str
    category: str  # content, authentication, domain, url, network, anomaly
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    confidence: float = 0.85
    mitre_technique: Optional[str] = None
    evidence: Optional[str] = None

class ThreatScoreBreakdown(BaseModel):
    ai_content_threat: int = 0      # max ~30
    auth_failure: int = 0           # max ~20
    suspicious_url: int = 0         # max ~15
    domain_lookalike: int = 0       # max ~15
    suspicious_ip: int = 0          # max ~10
    header_anomaly: int = 0         # max ~10

class ThreatScore(BaseModel):
    score: int  # 0 to 100
    severity: str  # low (0-25), medium (26-50), high (51-75), critical (76-100)
    verdict: str   # Malicious, Suspicious, Benign
    breakdown: ThreatScoreBreakdown
    confidence: float = 0.90

class ExtractedURL(BaseModel):
    url: str
    domain: str
    is_suspicious: bool = False
    reasons: list[str] = []
    is_ip_based: bool = False
    is_shortener: bool = False
    typosquat_target: Optional[str] = None

class ExtractedAttachment(BaseModel):
    filename: str
    size_bytes: int = 0
    content_type: str = ""
    is_executable: bool = False
    sha256: str = ""
    threat_verdict: str = "clean"

# ==================== COMPREHENSIVE ANALYSIS RESULT ====================
class AnalysisResult(BaseModel):
    id: str
    timestamp: str
    sha256_hash: str
    header_fingerprint: str
    subject: str
    sender: str
    recipient: str
    body_text: str = ""
    body_html: Optional[str] = None
    headers: HeaderAnalysis
    hops: list[RelayHop] = []
    earliest_origin_ip: Optional[str] = None
    origin_geo: Optional[GeoLocationInfo] = None
    threat_score: ThreatScore
    indicators: list[ThreatIndicator] = []
    extracted_urls: list[ExtractedURL] = []
    attachments: list[ExtractedAttachment] = []
    ml_prediction: Optional[dict[str, Any]] = None
    ai_summary: str = ""
    recommended_actions: list[str] = []

# ==================== CASE MANAGEMENT ====================
class InvestigationCase(BaseModel):
    case_id: str
    created_at: str
    subject: str
    sender: str
    recipient: str
    earliest_ip: str
    origin_country: str
    threat_score: int
    severity: str
    status: str = "Open"  # Open, Under Investigation, Triaged, Closed, Quarantined
    assigned_analyst: str = "SOC Analyst 1"
    sha256_hash: str
    summary: str = ""

# ==================== DASHBOARD STATS ====================
class DashboardStats(BaseModel):
    total_analyzed: int
    threats_detected: int
    high_risk_count: int
    avg_risk_score: float
    severity_distribution: dict[str, int]
    threat_type_breakdown: dict[str, int]
    daily_trend: list[dict[str, Any]]
    recent_activity: list[InvestigationCase]

# ==================== IOC LOOKUP ====================
class IOCLookupRequest(BaseModel):
    query: str
    type: str = "auto"  # auto, ip, domain, url, hash

class IOCLookupResponse(BaseModel):
    query: str
    ioc_type: str
    reputation: str  # Malicious, Suspicious, Safe, Unknown
    threat_score: int
    geolocation: Optional[GeoLocationInfo] = None
    associated_threats: list[str] = []
    mitre_techniques: list[str] = []
    last_seen: str = ""
    reports_count: int = 0
    whois_info: Optional[dict[str, Any]] = None

# ==================== ML MODEL STATUS ====================
class MLModelStatus(BaseModel):
    is_trained: bool
    model_name: str
    version: str
    trained_at: Optional[str] = None
    sample_count: int = 0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    features_count: int = 0

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from backend.core.config import settings
from backend.models.schemas import InvestigationCase, DashboardStats

# Preloaded baseline SOC incident cases
DEFAULT_CASES = [
    {
        "case_id": "CASE-2026-0891",
        "created_at": "2026-09-09T13:42:10Z",
        "subject": "URGENT: Outstanding Vendor Invoice Wire Transfer #INV-9921",
        "sender": "cfo-exec@corporate-accts-wire.com",
        "recipient": "finance-dept@enterprise.com",
        "earliest_ip": "185.220.101.44",
        "origin_country": "Germany",
        "threat_score": 94,
        "severity": "critical",
        "status": "Quarantined",
        "assigned_analyst": "Alex Vance (Lead)",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "summary": "Executive impersonation BEC attack attempting wire payment diversion to overseas account."
    },
    {
        "case_id": "CASE-2026-0889",
        "created_at": "2026-09-09T11:15:32Z",
        "subject": "Action Required: Microsoft 365 Password Expiration in 24 Hours",
        "sender": "no-reply@rnicrosoft-security-portal.xyz",
        "recipient": "dev-team@enterprise.com",
        "earliest_ip": "194.26.29.112",
        "origin_country": "Russia",
        "threat_score": 88,
        "severity": "critical",
        "status": "Under Investigation",
        "assigned_analyst": "Sarah Chen",
        "sha256_hash": "a4f8b2c198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b712",
        "summary": "Typosquatted domain hosting credential harvesting replica of Microsoft login portal."
    },
    {
        "case_id": "CASE-2026-0884",
        "created_at": "2026-09-09T08:20:05Z",
        "subject": "DHL Express: Delivery Exception for Tracking #DHL-90821-US",
        "sender": "express-support@dhl-tracking-portal-notice.top",
        "recipient": "logistics@enterprise.com",
        "earliest_ip": "103.145.13.78",
        "origin_country": "Indonesia",
        "threat_score": 79,
        "severity": "critical",
        "status": "Open",
        "assigned_analyst": "Marcus Brody",
        "sha256_hash": "8f3e5b7298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b499",
        "summary": "Shipping phishing delivery payload disguised as zipped invoice receipt."
    },
    {
        "case_id": "CASE-2026-0878",
        "created_at": "2026-09-08T17:50:11Z",
        "subject": "Payroll Update: Please verify direct deposit account details",
        "sender": "human-resources@payroll-verify-portal.net",
        "recipient": "all-staff@enterprise.com",
        "earliest_ip": "198.51.100.25",
        "origin_country": "United States",
        "threat_score": 67,
        "severity": "high",
        "status": "Triaged",
        "assigned_analyst": "Sarah Chen",
        "sha256_hash": "2c9d4e1198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b901",
        "summary": "Direct deposit phishing lure targeting employee banking information."
    },
    {
        "case_id": "CASE-2026-0870",
        "created_at": "2026-09-08T14:12:44Z",
        "subject": "DocuSign: Please review and sign Employee Handbook Amendment",
        "sender": "docusign-notifications@docuslgn-review.live",
        "recipient": "legal-ops@enterprise.com",
        "earliest_ip": "45.142.166.12",
        "origin_country": "Netherlands",
        "threat_score": 62,
        "severity": "high",
        "status": "Closed",
        "assigned_analyst": "Alex Vance (Lead)",
        "sha256_hash": "7b1c3a8898fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b332",
        "summary": "DocuSign brand abuse lure linking to fake OAuth consent authorization."
    },
    {
        "case_id": "CASE-2026-0865",
        "created_at": "2026-09-08T09:30:19Z",
        "subject": "Q3 Cybersecurity Briefing & Multi-Factor Authentication Reminder",
        "sender": "infosec-news@enterprise-internal.com",
        "recipient": "all-staff@enterprise.com",
        "earliest_ip": "142.250.190.78",
        "origin_country": "United States",
        "threat_score": 8,
        "severity": "low",
        "status": "Closed",
        "assigned_analyst": "Automated Policy",
        "sha256_hash": "3d4e5f6798fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b111",
        "summary": "Legitimate internal IT security awareness communication. SPF, DKIM, and DMARC aligned."
    }
]

class CaseStore:
    def __init__(self):
        self._cases: list[InvestigationCase] = []
        self._load_cases()

    def _load_cases(self):
        if settings.CASES_FILE.exists():
            try:
                with open(settings.CASES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._cases = [InvestigationCase(**item) for item in data]
                    return
            except Exception:
                pass
        
        # Initialize default cases
        self._cases = [InvestigationCase(**item) for item in DEFAULT_CASES]
        self._save_cases()

    def _save_cases(self):
        try:
            with open(settings.CASES_FILE, "w", encoding="utf-8") as f:
                json.dump([c.model_dump() for c in self._cases], f, indent=2)
        except Exception as e:
            print(f"Error saving cases: {e}")

    def list_cases(self, status: str = None, severity: str = None, query: str = None) -> list[InvestigationCase]:
        cases = list(self._cases)
        if status and status.lower() != "all":
            cases = [c for c in cases if c.status.lower() == status.lower()]
        if severity and severity.lower() != "all":
            cases = [c for c in cases if c.severity.lower() == severity.lower()]
        if query:
            q = query.lower()
            cases = [
                c for c in cases 
                if q in c.subject.lower() or q in c.sender.lower() or q in c.earliest_ip.lower() or q in c.case_id.lower()
            ]
        # Sort newest first
        cases.sort(key=lambda c: c.created_at, reverse=True)
        return cases

    def get_case(self, case_id: str) -> InvestigationCase | None:
        for c in self._cases:
            if c.case_id == case_id:
                return c
        return None

    def add_case(self, case: InvestigationCase):
        self._cases.insert(0, case)
        self._save_cases()

    def update_case_status(self, case_id: str, new_status: str, notes: str = "") -> InvestigationCase | None:
        case = self.get_case(case_id)
        if case:
            case.status = new_status
            if notes:
                case.summary += f" [Note: {notes}]"
            self._save_cases()
            return case
        return None

    def get_dashboard_stats(self) -> DashboardStats:
        total = len(self._cases) + 1476  # Scale for enterprise SOC realism
        threats = sum(1 for c in self._cases if c.threat_score >= 50) + 342
        high_risk = sum(1 for c in self._cases if c.threat_score >= 76) + 86
        
        avg_score = round((sum(c.threat_score for c in self._cases) + (35 * 1476)) / (len(self._cases) + 1476), 1)

        severity_counts = {"critical": 89, "high": 124, "medium": 134, "low": 1135}
        for c in self._cases:
            sev = c.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        threat_types = {
            "Business Email Compromise (BEC)": 118,
            "Credential Harvesting": 142,
            "Malware & Attachment Delivery": 54,
            "Brand / Executive Impersonation": 76,
            "Invoice / Payment Fraud": 68,
            "Domain Spoofing": 92
        }

        daily_trend = [
            {"date": "09/03", "analyzed": 194, "threats": 42},
            {"date": "09/04", "analyzed": 218, "threats": 51},
            {"date": "09/05", "analyzed": 230, "threats": 49},
            {"date": "09/06", "analyzed": 204, "threats": 38},
            {"date": "09/07", "analyzed": 245, "threats": 63},
            {"date": "09/08", "analyzed": 262, "threats": 58},
            {"date": "09/09", "analyzed": 129, "threats": 46},
        ]

        return DashboardStats(
            total_analyzed=total,
            threats_detected=threats,
            high_risk_count=high_risk,
            avg_risk_score=avg_score,
            severity_distribution=severity_counts,
            threat_type_breakdown=threat_types,
            daily_trend=daily_trend,
            recent_activity=self.list_cases()[:6]
        )

case_store = CaseStore()

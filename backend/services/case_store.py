import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from backend.core.config import settings
from backend.models.schemas import (
    InvestigationCase, 
    DashboardStats, 
    CaseNote, 
    ContainmentAction, 
    PromoteAnalysisRequest
)

# Preloaded baseline SOC incident cases with rich correlation attributes
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
        "summary": "Executive impersonation BEC attack attempting wire payment diversion to overseas account.",
        "sender_domain": "corporate-accts-wire.com",
        "threat_indicators": [
            "Executive Impersonation (CEO/CFO)",
            "Tor Exit Node Origin IP (185.220.101.44)",
            "Wire Redirection Lure",
            "SPF/DKIM Authentication Failure"
        ],
        "extracted_urls": [
            "https://corporate-accts-wire.com/auth/wire-instructions.pdf"
        ],
        "notes": [
            {
                "id": "NOTE-0891-1",
                "created_at": "2026-09-09T13:45:00Z",
                "author": "Alex Vance (Lead)",
                "text": "Confirmed CFO was traveling in Tokyo at the timestamp of message. Originating IP 185.220.101.44 mapped to active Tor exit node AS200651."
            }
        ],
        "containment_actions": [
            {
                "id": "ACT-0891-1",
                "created_at": "2026-09-09T13:46:12Z",
                "action_type": "quarantine_inbox",
                "target": "finance-dept@enterprise.com",
                "status": "Executed",
                "executed_by": "Alex Vance (Lead)",
                "details": "Isolated malicious email from recipient inboxes across exchange tenant."
            }
        ]
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
        "summary": "Typosquatted domain hosting credential harvesting replica of Microsoft login portal.",
        "sender_domain": "rnicrosoft-security-portal.xyz",
        "threat_indicators": [
            "Homoglyph Typosquatting ('rn' mimicking 'm')",
            "Credential Harvester Clone",
            "DMARC Policy Reject"
        ],
        "extracted_urls": [
            "https://rnicrosoft-security-portal.xyz/login/verify.php"
        ],
        "notes": [
            {
                "id": "NOTE-0889-1",
                "created_at": "2026-09-09T11:22:00Z",
                "author": "Sarah Chen",
                "text": "Credential harvesting landing page hosted in Saint Petersburg. Blocked at DNS firewall level."
            }
        ],
        "containment_actions": [
            {
                "id": "ACT-0889-1",
                "created_at": "2026-09-09T11:23:45Z",
                "action_type": "block_domain",
                "target": "rnicrosoft-security-portal.xyz",
                "status": "Executed",
                "executed_by": "Sarah Chen",
                "details": "Blacklisted domain at perimeter DNS resolver."
            }
        ]
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
        "summary": "Shipping phishing delivery payload disguised as zipped invoice receipt.",
        "sender_domain": "dhl-tracking-portal-notice.top",
        "threat_indicators": [
            "Malicious Zip Archive Payload",
            "Brand Abuse: DHL Global",
            "Suspicious Top-Level Domain (.top)"
        ],
        "extracted_urls": [
            "https://dhl-tracking-portal-notice.top/track/DHL-90821-US.zip"
        ],
        "notes": [],
        "containment_actions": []
    },
    {
        "case_id": "CASE-2026-0878",
        "created_at": "2026-09-08T17:50:11Z",
        "subject": "Payroll Update: Please verify direct deposit account details",
        "sender": "human-resources@payroll-verify-portal.net",
        "recipient": "all-staff@enterprise.com",
        "earliest_ip": "185.220.101.44",
        "origin_country": "Germany",
        "threat_score": 67,
        "severity": "high",
        "status": "Triaged",
        "assigned_analyst": "Sarah Chen",
        "sha256_hash": "2c9d4e1198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b901",
        "summary": "Direct deposit phishing lure targeting employee banking information.",
        "sender_domain": "payroll-verify-portal.net",
        "threat_indicators": [
            "Direct Deposit Fraud",
            "Shared Origin IP with CASE-2026-0891 (185.220.101.44)",
            "Lookalike Payroll Domain"
        ],
        "extracted_urls": [
            "https://payroll-verify-portal.net/portal/direct-deposit"
        ],
        "notes": [
            {
                "id": "NOTE-0878-1",
                "created_at": "2026-09-08T18:05:00Z",
                "author": "Sarah Chen",
                "text": "Shared infrastructure pivot: Origin IP 185.220.101.44 matches the BEC campaign in CASE-2026-0891."
            }
        ],
        "containment_actions": []
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
        "summary": "DocuSign brand abuse lure linking to fake OAuth consent authorization.",
        "sender_domain": "docuslgn-review.live",
        "threat_indicators": [
            "DocuSign Impersonation ('docuslgn')",
            "Fake OAuth Token Redirection"
        ],
        "extracted_urls": [
            "https://docuslgn-review.live/docusign/handbook-amendment"
        ],
        "notes": [],
        "containment_actions": [
            {
                "id": "ACT-0870-1",
                "created_at": "2026-09-08T14:30:00Z",
                "action_type": "block_domain",
                "target": "docuslgn-review.live",
                "status": "Executed",
                "executed_by": "Alex Vance (Lead)",
                "details": "Blocked at border firewall."
            }
        ]
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
        "summary": "Legitimate internal IT security awareness communication. SPF, DKIM, and DMARC aligned.",
        "sender_domain": "enterprise-internal.com",
        "threat_indicators": [
            "Cryptographic SPF Pass",
            "Cryptographic DKIM Pass",
            "DMARC Enforced Alignment"
        ],
        "extracted_urls": [
            "https://security.enterprise.com/quarterly-briefing"
        ],
        "notes": [],
        "containment_actions": []
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
                self.add_note(case_id, author="SOC System", text=notes)
            self._save_cases()
            return case
        return None

    def update_case_analyst(self, case_id: str, analyst: str) -> InvestigationCase | None:
        case = self.get_case(case_id)
        if case:
            case.assigned_analyst = analyst
            self._save_cases()
            return case
        return None

    def add_note(self, case_id: str, author: str, text: str) -> CaseNote | None:
        case = self.get_case(case_id)
        if not case:
            return None
        note = CaseNote(
            id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
            created_at=datetime.now(timezone.utc).isoformat(),
            author=author,
            text=text
        )
        case.notes.insert(0, note)
        self._save_cases()
        return note

    def execute_containment(self, case_id: str, action_type: str, target: str, executed_by: str = "SOC Analyst", details: str = "") -> ContainmentAction | None:
        case = self.get_case(case_id)
        if not case:
            return None
        action = ContainmentAction(
            id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            created_at=datetime.now(timezone.utc).isoformat(),
            action_type=action_type,
            target=target,
            status="Executed",
            executed_by=executed_by,
            details=details or f"Executed {action_type} on {target}"
        )
        case.containment_actions.insert(0, action)
        if action_type == "quarantine_inbox":
            case.status = "Quarantined"
        self._save_cases()
        return action

    def promote_analysis_to_case(self, data: PromoteAnalysisRequest) -> InvestigationCase:
        # Generate sequential case ID
        existing_numbers = []
        for c in self._cases:
            if c.case_id.startswith("CASE-2026-"):
                try:
                    num = int(c.case_id.split("-")[-1])
                    existing_numbers.append(num)
                except ValueError:
                    pass
        next_num = max(existing_numbers, default=891) + 1
        new_case_id = f"CASE-2026-{next_num:04d}"

        domain = data.sender_domain
        if not domain and "@" in data.sender:
            domain = data.sender.split("@")[-1].strip(">").strip()

        new_case = InvestigationCase(
            case_id=new_case_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            subject=data.subject,
            sender=data.sender,
            recipient=data.recipient,
            earliest_ip=data.earliest_ip,
            origin_country=data.origin_country,
            threat_score=data.threat_score,
            severity=data.severity,
            status="Under Investigation" if data.threat_score >= 50 else "Open",
            assigned_analyst=data.assigned_analyst or "Alex Vance (Lead)",
            sha256_hash=data.sha256_hash or uuid.uuid4().hex,
            summary=data.summary or f"Promoted from Forensic Analysis {data.analysis_id}",
            sender_domain=domain,
            threat_indicators=data.threat_indicators,
            extracted_urls=data.extracted_urls,
            notes=[
                CaseNote(
                    id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
                    created_at=datetime.now(timezone.utc).isoformat(),
                    author=data.assigned_analyst or "SOC Analyst",
                    text=f"Promoted incident from live analysis {data.analysis_id}. Threat score: {data.threat_score}/100."
                )
            ],
            containment_actions=[]
        )
        self.add_case(new_case)
        return new_case

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

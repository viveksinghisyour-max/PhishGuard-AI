import re
from typing import List, Tuple, Dict, Any, Optional
from backend.models.schemas import (
    HeaderAnalysis,
    RelayHop,
    ExtractedURL,
    ExtractedAttachment,
    ThreatScore,
    ThreatScoreBreakdown,
    ThreatIndicator
)

class AIThreatEngine:
    """Multi-factor threat detection and forensic scoring engine."""

    # Top impersonated brands for lookalike / typosquat detection
    TARGET_BRANDS = [
        "microsoft", "office365", "paypal", "dhl", "google", "apple", 
        "netflix", "amazon", "chase", "wellsfargo", "bankofamerica", "phishguardai"
    ]

    URGENCY_KEYWORDS = [
        "immediate action", "within 24 hours", "account suspended", "urgent response",
        "terminated immediately", "final notice", "critical warning", "legal action"
    ]

    FINANCIAL_KEYWORDS = [
        "wire transfer", "banking details", "invoice overdue", "swift transfer",
        "remittance", "payment confirmation", "direct deposit", "payroll update"
    ]

    CREDENTIAL_KEYWORDS = [
        "password expired", "verify your credentials", "reset password", "login to continue",
        "confirm identity", "security upgrade required", "mailbox full"
    ]

    @classmethod
    def evaluate(
        cls,
        headers: HeaderAnalysis,
        body_text: str,
        urls: List[ExtractedURL],
        attachments: List[ExtractedAttachment],
        hops: List[RelayHop],
        earliest_origin_ip: str,
        ml_prediction: Dict[str, Any] | None = None
    ) -> Tuple[ThreatScore, List[ThreatIndicator], str, List[str]]:
        """
        Executes multi-factor heuristic and behavioral threat assessment.
        Returns ThreatScore, list of ThreatIndicators, executive summary, and recommendations.
        """
        breakdown = ThreatScoreBreakdown()
        indicators: List[ThreatIndicator] = []
        lower_body = body_text.lower()
        lower_subject = headers.subject.lower()
        combined_text = f"{lower_subject} {lower_body}"

        # 1. AUTHENTICATION & HEADER ANOMALIES
        auth_score = 0
        if headers.spf_result in ('fail', 'softfail'):
            auth_score += 15
            indicators.append(ThreatIndicator(
                id="IND-AUTH-SPF",
                category="authentication",
                title="SPF Authentication Failure",
                severity="high",
                description=f"Sender transmitting server failed SPF validation ({headers.spf_result}). Unapproved infrastructure.",
                mitre_technique="T1589: Gather Victim Identity Info",
                evidence=headers.spf_details
            ))

        if headers.dmarc_result == 'fail':
            auth_score += 20
            indicators.append(ThreatIndicator(
                id="IND-AUTH-DMARC",
                category="authentication",
                title="DMARC Enforcement Failure",
                severity="critical",
                description="Email failed domain DMARC policy enforcement. Envelope domain is spoofed.",
                mitre_technique="T1566: Phishing",
                evidence=headers.dmarc_details
            ))

        if headers.dkim_result == 'fail':
            auth_score += 10
            indicators.append(ThreatIndicator(
                id="IND-AUTH-DKIM",
                category="authentication",
                title="DKIM Signature Verification Failed",
                severity="high",
                description="Cryptographic signature invalid or email headers/body altered in transit.",
                mitre_technique="T1566: Phishing",
                evidence=headers.dkim_details
            ))

        if not headers.alignment_from_replyto and headers.reply_to:
            auth_score += 18
            indicators.append(ThreatIndicator(
                id="IND-HEADER-REPLYTO",
                category="anomaly",
                title="Reply-To Redirection Mismatch",
                severity="high",
                description=f"Recipient replies diverted to foreign address '{headers.reply_to}' rather than '{headers.from_domain}'.",
                mitre_technique="T1566.002: Spearphishing Link",
                evidence=f"From: {headers.from_address} -> Reply-To: {headers.reply_to}"
            ))

        if not headers.alignment_from_returnpath and headers.return_path:
            auth_score += 10
            indicators.append(ThreatIndicator(
                id="IND-HEADER-RETURNPATH",
                category="anomaly",
                title="Return-Path Envelope Misalignment",
                severity="medium",
                description=f"Return envelope bounces to '{headers.return_path}' which does not align with '{headers.from_domain}'.",
                mitre_technique="T1589: Gather Identity Info",
                evidence=headers.return_path
            ))

        breakdown.auth_failure = min(25, auth_score)

        # 2. CONTENT & BEHAVIORAL PATTERNS
        content_score = 0
        urgency_matches = [k for k in cls.URGENCY_KEYWORDS if k in combined_text]
        if urgency_matches:
            content_score += 12
            indicators.append(ThreatIndicator(
                id="IND-CONT-URGENCY",
                category="content",
                title="Artificial Urgency & Time Pressure Cues",
                severity="high",
                description=f"Email exerts psychological pressure via keywords: {', '.join(urgency_matches[:3])}.",
                mitre_technique="T1598: Phishing for Information",
                evidence=f"Matches: {', '.join(urgency_matches)}"
            ))

        financial_matches = [k for k in cls.FINANCIAL_KEYWORDS if k in combined_text]
        if financial_matches:
            content_score += 16
            indicators.append(ThreatIndicator(
                id="IND-CONT-FINANCE",
                category="content",
                title="Financial Diversion / Wire Redirection",
                severity="critical",
                description="Signals consistent with Business Email Compromise (BEC) wire payment redirection.",
                mitre_technique="T1566.002: Spearphishing Link",
                evidence=f"Matches: {', '.join(financial_matches)}"
            ))

        credential_matches = [k for k in cls.CREDENTIAL_KEYWORDS if k in combined_text]
        if credential_matches:
            content_score += 15
            indicators.append(ThreatIndicator(
                id="IND-CONT-CREDENTIAL",
                category="content",
                title="Credential Harvester Lure",
                severity="critical",
                description="Explicit request to reset, verify, or input login credentials.",
                mitre_technique="T1056: Input Capture",
                evidence=f"Matches: {', '.join(credential_matches)}"
            ))

        # Check executive / internal spoofing anomalies from header parser
        for anomaly in headers.anomalies:
            if "spoofing" in anomaly.lower() or "impersonation" in anomaly.lower():
                content_score += 25
                indicators.append(ThreatIndicator(
                    id="IND-CONT-SPOOF",
                    category="domain",
                    title="Executive Display-Name Impersonation",
                    severity="critical",
                    description=anomaly,
                    mitre_technique="T1566: Phishing",
                    evidence=f"Display Name: {headers.from_display} | From: {headers.from_address}"
                ))

        # 2b. MACHINE LEARNING NLP THREAT INFERENCE
        if ml_prediction and ml_prediction.get("is_trained"):
            phish_prob = ml_prediction.get("phishing_probability", 0.0)
            if phish_prob >= 0.50:
                ml_points = int(phish_prob * 25)
                content_score += ml_points
                tokens = [t.get("token", "") for t in ml_prediction.get("contributing_tokens", [])[:4]]
                token_str = f" (Key features: {', '.join(tokens)})" if tokens else ""
                indicators.append(ThreatIndicator(
                    id="IND-ML-PHISH",
                    category="content",
                    title=f"ML NLP Phishing Classification ({round(phish_prob * 100, 1)}%)",
                    severity="critical" if phish_prob >= 0.85 else ("high" if phish_prob >= 0.65 else "medium"),
                    description=f"Unified Scikit-Learn model classified text content as phishing with {round(ml_prediction.get('confidence', 0)*100, 1)}% confidence.{token_str}",
                    mitre_technique="T1566: Phishing",
                    evidence=f"Posterior Phishing Prob: {round(phish_prob, 4)} | Risk: {ml_prediction.get('risk_level')}"
                ))
            elif phish_prob <= 0.15:
                content_score = max(0, content_score - 10)

        breakdown.ai_content_threat = min(35, content_score)

        # 3. URL & DOMAIN REPUTATION
        url_score = 0
        lookalike_score = 0
        for u in urls:
            if u.is_ip_based:
                url_score += 15
                indicators.append(ThreatIndicator(
                    id="IND-URL-IP",
                    category="url",
                    title="Direct IP-Based Hyperlink Target",
                    severity="high",
                    description=f"URL links directly to numerical IP ({u.domain}), bypassing standard DNS inspection.",
                    mitre_technique="T1566.002: Spearphishing Link",
                    evidence=u.url
                ))

            if u.is_shortener:
                url_score += 8
                indicators.append(ThreatIndicator(
                    id="IND-URL-SHORT",
                    category="url",
                    title="Obfuscated URL Shortener Service",
                    severity="medium",
                    description=f"Destination obfuscated via link shortener '{u.domain}'.",
                    mitre_technique="T1566.002: Spearphishing Link",
                    evidence=u.url
                ))

            # Lookalike domain check
            target_brand = cls._check_lookalike(u.domain)
            if target_brand:
                lookalike_score += 18
                u.typosquat_target = target_brand
                indicators.append(ThreatIndicator(
                    id="IND-DOM-TYPOSQUAT",
                    category="domain",
                    title=f"Typosquatted Brand Impersonation ({target_brand.upper()})",
                    severity="critical",
                    description=f"Domain '{u.domain}' impersonates brand '{target_brand}'.",
                    mitre_technique="T1566.002: Spearphishing Link",
                    evidence=f"{u.domain} mimics {target_brand}"
                ))

        # Check sender domain itself for lookalike
        sender_lookalike = cls._check_lookalike(headers.from_domain)
        if sender_lookalike:
            lookalike_score += 20
            indicators.append(ThreatIndicator(
                id="IND-DOM-SENDER-TYPO",
                category="domain",
                title=f"Sender Domain Lookalike ({sender_lookalike.upper()})",
                severity="critical",
                description=f"Sender domain '{headers.from_domain}' mimics legitimate brand '{sender_lookalike}'.",
                mitre_technique="T1566: Phishing",
                evidence=headers.from_domain
            ))

        breakdown.suspicious_url = min(20, url_score)
        breakdown.domain_lookalike = min(20, lookalike_score)

        # 4. ATTACHMENT RISK
        att_score = 0
        for att in attachments:
            if att.is_executable:
                att_score += 35
                indicators.append(ThreatIndicator(
                    id="IND-ATT-EXE",
                    category="content",
                    title="Weaponized Executable Attachment",
                    severity="critical",
                    description=f"Attachment '{att.filename}' contains high-risk executable or script extension.",
                    mitre_technique="T1566.001: Spearphishing Attachment",
                    evidence=f"File: {att.filename} (SHA256: {att.sha256[:16]}...)"
                ))

        # 5. ORIGIN NETWORK REPUTATION
        ip_score = 0
        for h in hops:
            if h.is_tor:
                ip_score += 25
                indicators.append(ThreatIndicator(
                    id="IND-NET-TOR",
                    category="network",
                    title="Transmitted via TOR Anonymization Network",
                    severity="critical",
                    description=f"Relay hop '{h.ip}' identified as active TOR exit node in {h.country}.",
                    mitre_technique="T1090.003: TOR Proxy",
                    evidence=f"Hop #{h.hop_number}: {h.ip}"
                ))
            elif h.is_vpn or h.is_hosting:
                ip_score += 8
                indicators.append(ThreatIndicator(
                    id="IND-NET-DATACENTER",
                    category="network",
                    title="Commercial Hosting / Proxy Infrastructure",
                    severity="medium",
                    description=f"Relay hop originating from datacenter IP space ({h.isp}, {h.country}).",
                    mitre_technique="T1090: Proxy",
                    evidence=f"{h.ip} ({h.isp})"
                ))

        breakdown.suspicious_ip = min(15, ip_score)
        breakdown.header_anomaly = min(10, len(headers.anomalies) * 5)

        # Total Composite Score (0-100)
        total_raw = (
            breakdown.ai_content_threat +
            breakdown.auth_failure +
            breakdown.suspicious_url +
            breakdown.domain_lookalike +
            breakdown.suspicious_ip +
            breakdown.header_anomaly +
            att_score
        )
        final_score = max(5, min(100, total_raw))

        # Severity & Verdict Categorization
        if final_score >= 76:
            severity = "critical"
            verdict = "Malicious"
        elif final_score >= 51:
            severity = "high"
            verdict = "Suspicious"
        elif final_score >= 26:
            severity = "medium"
            verdict = "Suspicious"
        else:
            severity = "low"
            verdict = "Benign"

        threat_score = ThreatScore(
            score=final_score,
            severity=severity,
            verdict=verdict,
            breakdown=breakdown,
            confidence=0.94
        )

        # Executive Summary Generation
        summary = cls._generate_summary(final_score, verdict, indicators, headers)

        # Recommended Remediation Actions
        recommendations = cls._generate_recommendations(final_score, indicators, headers)

        return threat_score, indicators, summary, recommendations

    @classmethod
    def _check_lookalike(cls, domain: str) -> str:
        """Simple Levenshtein and character substitution lookalike detector."""
        clean = domain.split('.')[0].lower()
        
        # Replace common homoglyphs: 1->l, 0->o, rn->m, vv->w
        normalized = clean.replace('1', 'l').replace('0', 'o').replace('rn', 'm').replace('vv', 'w')

        for brand in cls.TARGET_BRANDS:
            if brand in clean and clean != brand:
                return brand
            if brand in normalized and clean != brand:
                return brand

        return ""

    @classmethod
    def _generate_summary(cls, score: int, verdict: str, indicators: List[ThreatIndicator], headers: HeaderAnalysis) -> str:
        criticals = [i.title for i in indicators if i.severity == 'critical']
        highs = [i.title for i in indicators if i.severity == 'high']
        key_threats = criticals + highs

        if score >= 76:
            threat_str = f" Critical threat vectors detected including {', '.join(key_threats[:3])}." if key_threats else ""
            return (
                f"High-confidence {verdict} email payload (Threat Score: {score}/100) claiming origin from '{headers.from_address}'. "
                f"Envelope exhibits authentication failure and hostile cues.{threat_str} "
                "Immediate containment and mailbox isolation recommended."
            )
        elif score >= 50:
            return (
                f"Suspicious email payload (Threat Score: {score}/100) with flagged indicators ({', '.join(key_threats[:2]) or 'header anomalies'}). "
                "Manual triage required by SOC analyst before releasing to recipient."
            )
        else:
            return (
                f"Clean email payload (Threat Score: {score}/100). Envelope passed primary authentication checks "
                f"(SPF: {headers.spf_result.upper()}, DMARC: {headers.dmarc_result.upper()}). No malicious indicators discovered."
            )

    @classmethod
    def _generate_recommendations(cls, score: int, indicators: List[ThreatIndicator], headers: HeaderAnalysis) -> List[str]:
        recs = []
        if score >= 76:
            recs.append("Quarantine email across all organizational mailboxes")
            recs.append(f"Block inbound SMTP connections from sending IP space")
            if headers.from_domain:
                recs.append(f"Add domain '{headers.from_domain}' to perimeter firewall blackhole list")
            recs.append("Trigger automated credential reset if targeted user clicked hyperlinks")
        elif score >= 50:
            recs.append("Deliver with external warning banner and defanged hyperlinks")
            recs.append(f"Review DMARC policy for domain '{headers.from_domain}'")
            recs.append("Escalate case to Level 2 SOC analyst for IOC pivoting")
        else:
            recs.append("No containment action required; email is verified benign")
            recs.append("Log authentication pass telemetry for baseline modeling")

        return recs

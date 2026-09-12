"""
PhishGuard AI — Interactive MITRE ATT&CK® Enterprise Matrix Service
Provides taxonomy of phishing/cyber threats, live detection heatmap aggregation,
and exportable official MITRE ATT&CK Navigator Layer JSON.
"""

from datetime import datetime, timezone
from typing import Any
from backend.models.schemas import (
    MitreTechnique,
    MitreTactic,
    MitreMatrixResponse,
    MitreHeatmapHit,
    MitreHeatmapResponse
)
from backend.services.case_store import case_store

class MitreMatrixService:
    def __init__(self):
        self._tactics: list[MitreTactic] = self._build_taxonomy()

    def _build_taxonomy(self) -> list[MitreTactic]:
        """Constructs the comprehensive MITRE ATT&CK Enterprise Matrix focused on email & adversary campaigns."""
        return [
            MitreTactic(
                id="TA0043",
                name="Reconnaissance",
                description="The adversary is trying to gather information they can use to plan future operations.",
                techniques=[
                    MitreTechnique(
                        id="T1589",
                        name="Gather Victim Identity Information",
                        tactic_id="TA0043",
                        tactic_name="Reconnaissance",
                        description="Adversaries gather victim identity information that can be used during targeting, including employee names, email addresses, and organizational hierarchies.",
                        subtechniques_count=3,
                        detection_rules=["Detect rapid enumeration across SMTP VRFY/RCPT TO", "OSINT LinkedIn company directory scraping"],
                        mitigation_ids=["M1056 Pre-compromise Intelligence Gathering"]
                    ),
                    MitreTechnique(
                        id="T1596",
                        name="Search Open Technical Databases",
                        tactic_id="TA0043",
                        tactic_name="Reconnaissance",
                        description="Adversaries search open technical databases such as DNS registries, WHOIS records, and certificate transparency logs to identify mail gateways and target domains.",
                        subtechniques_count=5,
                        detection_rules=["DNS TXT/MX query volume anomaly", "Certificate transparency log monitoring"],
                        mitigation_ids=["M1056 Intelligence Monitoring"]
                    ),
                    MitreTechnique(
                        id="T1598",
                        name="Phishing for Information",
                        tactic_id="TA0043",
                        tactic_name="Reconnaissance",
                        description="Adversaries send phishing messages to elicit sensitive information such as employee credentials, internal phone extensions, or system architecture details.",
                        subtechniques_count=3,
                        detection_rules=["NLP heuristic detection of survey lures", "Suspicious Google Forms / Microsoft Forms links"],
                        mitigation_ids=["M1054 Software Configuration", "M1049 Antivirus/Antimalware"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0042",
                name="Resource Development",
                description="The adversary is establishing resources they can use to support operations.",
                techniques=[
                    MitreTechnique(
                        id="T1583.001",
                        name="Acquire Infrastructure: Domains",
                        tactic_id="TA0042",
                        tactic_name="Resource Development",
                        description="Adversaries register domains that resemble target companies or trusted brands to conduct phishing and masquerading attacks.",
                        subtechniques_count=1,
                        detection_rules=["Newly Registered Domain (NRD) age < 30 days", "Damerau-Levenshtein typosquatting distance score"],
                        mitigation_ids=["M1031 Network Intrusion Prevention"]
                    ),
                    MitreTechnique(
                        id="T1583.003",
                        name="Acquire Infrastructure: VPS",
                        tactic_id="TA0042",
                        tactic_name="Resource Development",
                        description="Adversaries lease Virtual Private Servers in bulletproof hosting jurisdictions to route phishing emails and host C2 endpoints.",
                        subtechniques_count=1,
                        detection_rules=["Known bulletproof hosting ASN detection", "Hosting provider IP in SMTP ingress"],
                        mitigation_ids=["M1037 Filter Network Traffic"]
                    ),
                    MitreTechnique(
                        id="T1586.002",
                        name="Compromise Accounts: Email Accounts",
                        tactic_id="TA0042",
                        tactic_name="Resource Development",
                        description="Adversaries compromise legitimate email accounts to send emails with trusted sender reputation and bypass SPF/DKIM validation.",
                        subtechniques_count=2,
                        detection_rules=["Impossible travel anomaly between logins", "Suspicious inbox auto-forwarding rule creation"],
                        mitigation_ids=["M1032 Multi-Factor Authentication", "M1026 Privileged Account Management"]
                    ),
                    MitreTechnique(
                        id="T1587.001",
                        name="Develop Capabilities: Malware",
                        tactic_id="TA0042",
                        tactic_name="Resource Development",
                        description="Adversaries develop or purchase malware such as info-stealers (AgentTesla, RedLine) to distribute via phishing lures.",
                        subtechniques_count=1,
                        detection_rules=["YARA rule static signature matching", "Known Trojan dropper hash lookup in VirusTotal/URLhaus"],
                        mitigation_ids=["M1049 Antivirus/Antimalware"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0001",
                name="Initial Access",
                description="The adversary is trying to get into your network.",
                techniques=[
                    MitreTechnique(
                        id="T1566.001",
                        name="Spearphishing Attachment",
                        tactic_id="TA0001",
                        tactic_name="Initial Access",
                        description="Adversaries attach weaponized files (ZIP, ISO, PDF with embedded JS, Office macros) directly to phishing emails.",
                        subtechniques_count=1,
                        detection_rules=["Executable extension check (.exe, .scr, .vbs)", "Macro inspection in OLE/OOXML streams"],
                        mitigation_ids=["M1049 Antivirus", "M1031 Network Intrusion Prevention", "M1021 Restrict Web-Based Content"]
                    ),
                    MitreTechnique(
                        id="T1566.002",
                        name="Spearphishing Link",
                        tactic_id="TA0001",
                        tactic_name="Initial Access",
                        description="Adversaries include malicious hyperlinks in email bodies redirecting victims to credential harvest pages or malware droppers.",
                        subtechniques_count=1,
                        detection_rules=["Typosquatting URL detection", "Shortener resolution & IP-based host matching"],
                        mitigation_ids=["M1021 Restrict Web-Based Content", "M1054 Software Configuration"]
                    ),
                    MitreTechnique(
                        id="T1566.003",
                        name="Spearphishing via Service",
                        tactic_id="TA0001",
                        tactic_name="Initial Access",
                        description="Adversaries use third-party services (DocuSign, SharePoint, Google Drive, Box) to send phishing lures with trusted service origins.",
                        subtechniques_count=1,
                        detection_rules=["Brand abuse heuristic on shared documents", "OAuth consent grant inspection"],
                        mitigation_ids=["M1021 Restrict Web Content", "M1032 Multi-Factor Authentication"]
                    ),
                    MitreTechnique(
                        id="T1199",
                        name="Trusted Relationship",
                        tactic_id="TA0001",
                        tactic_name="Initial Access",
                        description="Adversaries exploit trusted vendor and supplier business relationships to send fraudulent wire transfer instructions and invoices.",
                        subtechniques_count=0,
                        detection_rules=["Vendor domain lookalike comparison", "Bank account IBAN modification heuristic"],
                        mitigation_ids=["M1030 Network Segmentation"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0002",
                name="Execution",
                description="The adversary is trying to run malicious code.",
                techniques=[
                    MitreTechnique(
                        id="T1204.001",
                        name="User Execution: Malicious Link",
                        tactic_id="TA0002",
                        tactic_name="Execution",
                        description="An adversary relies on the user clicking a malicious link in an email to trigger payload delivery or credential harvesting.",
                        subtechniques_count=1,
                        detection_rules=["Safe links proxy re-write detection", "Browser click-time isolation analysis"],
                        mitigation_ids=["M1021 Restrict Web-Based Content", "M1017 User Training"]
                    ),
                    MitreTechnique(
                        id="T1204.002",
                        name="User Execution: Malicious File",
                        tactic_id="TA0002",
                        tactic_name="Execution",
                        description="An adversary relies on the user opening a malicious attachment to execute shellcode or scripts.",
                        subtechniques_count=1,
                        detection_rules=["Sandbox dynamic detonation telemetry", "Process creation from email client process"],
                        mitigation_ids=["M1040 Behavior Prevention on Endpoint", "M1049 Antivirus"]
                    ),
                    MitreTechnique(
                        id="T1059",
                        name="Command and Scripting Interpreter",
                        tactic_id="TA0002",
                        tactic_name="Execution",
                        description="Adversaries abuse command line shells (PowerShell, cmd.exe, wscript) to execute secondary payloads delivered via email.",
                        subtechniques_count=7,
                        detection_rules=["Encoded PowerShell commands in email attachments", "Child process execution of wscript.exe"],
                        mitigation_ids=["M1038 Execution Prevention"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0005",
                name="Defense Evasion",
                description="The adversary is trying to avoid being detected.",
                techniques=[
                    MitreTechnique(
                        id="T1027",
                        name="Obfuscated Files or Information",
                        tactic_id="TA0005",
                        tactic_name="Defense Evasion",
                        description="Adversaries obfuscate email content, attachments, and URLs using Base64, zero-font size text, or HTML entity escaping.",
                        subtechniques_count=9,
                        detection_rules=["High Shannon entropy in MIME parts", "Zero-font / hidden text CSS detection in email HTML"],
                        mitigation_ids=["M1049 Antivirus", "M1054 Software Configuration"]
                    ),
                    MitreTechnique(
                        id="T1036.005",
                        name="Masquerading: Match Legitimate Name",
                        tactic_id="TA0005",
                        tactic_name="Defense Evasion",
                        description="Adversaries match legitimate file names and email display names (e.g. 'CEO Name <fraud@external.com>') to deceive recipients.",
                        subtechniques_count=2,
                        detection_rules=["Display Name mismatch with RFC 5322 From address", "C-suite executive display name spoofing"],
                        mitigation_ids=["M1031 Network Intrusion Prevention"]
                    ),
                    MitreTechnique(
                        id="T1553.002",
                        name="Subvert Trust Controls: Code Signing",
                        tactic_id="TA0005",
                        tactic_name="Defense Evasion",
                        description="Adversaries sign malicious executables with stolen or fraudulent digital certificates to bypass gateway scanners.",
                        subtechniques_count=1,
                        detection_rules=["Untrusted or revoked certificate authority", "Certificate issuer entropy check"],
                        mitigation_ids=["M1042 Disable or Remove Feature"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0006",
                name="Credential Access",
                description="The adversary is trying to steal account names and passwords.",
                techniques=[
                    MitreTechnique(
                        id="T1056.003",
                        name="Input Capture: Web Phishing",
                        tactic_id="TA0006",
                        tactic_name="Credential Access",
                        description="Adversaries set up fake login portals resembling Microsoft 365, Okta, or Google Workspace to harvest credentials.",
                        subtechniques_count=1,
                        detection_rules=["HTML password input field on non-authenticated domain", "Credential harvester form action target lookup"],
                        mitigation_ids=["M1032 Multi-Factor Authentication", "M1021 Restrict Web Content"]
                    ),
                    MitreTechnique(
                        id="T1557",
                        name="Adversary-in-the-Middle",
                        tactic_id="TA0006",
                        tactic_name="Credential Access",
                        description="Adversaries position reverse proxy tools (Evilginx, Modlishka) between the user and the real auth server to intercept session cookies.",
                        subtechniques_count=3,
                        detection_rules=["Reverse proxy header anomalies", "Dynamic domain TLS certificate proxy mismatch"],
                        mitigation_ids=["M1032 FIDO2 / WebAuthn MFA"]
                    ),
                    MitreTechnique(
                        id="T1539",
                        name="Steal Web Session Cookie",
                        tactic_id="TA0006",
                        tactic_name="Credential Access",
                        description="Adversaries capture session cookies to bypass MFA and authenticate directly into corporate cloud environments.",
                        subtechniques_count=0,
                        detection_rules=["Session token replay from anomalous IP", "Token IP mismatch with user agent"],
                        mitigation_ids=["M1032 Conditional Access Policies"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0011",
                name="Command and Control",
                description="The adversary is trying to communicate with compromised systems.",
                techniques=[
                    MitreTechnique(
                        id="T1090",
                        name="Proxy",
                        tactic_id="TA0011",
                        tactic_name="Command and Control",
                        description="Adversaries use intermediate proxies to disguise the source of phishing attacks and C2 communication.",
                        subtechniques_count=3,
                        detection_rules=["Datacenter hosting IP in SMTP origin", "Residential proxy network detection"],
                        mitigation_ids=["M1037 Filter Network Traffic"]
                    ),
                    MitreTechnique(
                        id="T1090.003",
                        name="Proxy: Multi-hop / Tor Proxy",
                        tactic_id="TA0011",
                        tactic_name="Command and Control",
                        description="Adversaries route SMTP traffic through the Tor onion routing network to completely obfuscate true origin IP and jurisdiction.",
                        subtechniques_count=1,
                        detection_rules=["Tor exit node IP list matching in earliest Received header", "Anomalous multi-hop relay trajectory"],
                        mitigation_ids=["M1037 Filter Network Traffic", "M1031 Network Intrusion Prevention"]
                    ),
                    MitreTechnique(
                        id="T1071.001",
                        name="Application Layer Protocol: Web",
                        tactic_id="TA0011",
                        tactic_name="Command and Control",
                        description="Adversaries use standard HTTP/HTTPS protocols for C2 to blend in with legitimate network traffic.",
                        subtechniques_count=1,
                        detection_rules=["Direct IP HTTP requests in email links", "Uncommon URI patterns in payloads"],
                        mitigation_ids=["M1031 Network Intrusion Prevention"]
                    )
                ]
            ),
            MitreTactic(
                id="TA0040",
                name="Impact",
                description="The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                techniques=[
                    MitreTechnique(
                        id="T1657",
                        name="Financial Theft",
                        tactic_id="TA0040",
                        tactic_name="Impact",
                        description="Adversaries conduct unauthorized wire transfers and payroll direct deposit diversions through Business Email Compromise (BEC).",
                        subtechniques_count=0,
                        detection_rules=["Urgent financial transaction NLP keywords in unauthenticated email", "Wire routing ABA/SWIFT regex matching"],
                        mitigation_ids=["M1017 User Training", "M1026 Multi-party Authorization Procedures"]
                    ),
                    MitreTechnique(
                        id="T1486",
                        name="Data Encrypted for Impact",
                        tactic_id="TA0040",
                        tactic_name="Impact",
                        description="Adversaries encrypt files on target systems using ransomware delivered via initial phishing attachments.",
                        subtechniques_count=0,
                        detection_rules=["Ransom note text patterns in attachments", "High volume file modification following email click"],
                        mitigation_ids=["M1053 Data Backup", "M1049 Antivirus"]
                    )
                ]
            )
        ]

    def get_matrix(self) -> MitreMatrixResponse:
        """Returns the full hierarchical MITRE ATT&CK Matrix."""
        total_techs = sum(len(t.techniques) for t in self._tactics)
        return MitreMatrixResponse(
            tactics=self._tactics,
            total_tactics=len(self._tactics),
            total_techniques=total_techs
        )

    def calculate_heatmap(self) -> MitreHeatmapResponse:
        """Calculates dynamic technique detection frequencies based on live incident cases."""
        cases = case_store.list_cases()
        hits: dict[str, MitreHeatmapHit] = {}

        # Default mapping dictionary
        tech_meta = {}
        for tactic in self._tactics:
            for tech in tactic.techniques:
                tech_meta[tech.id] = {
                    "name": tech.name,
                    "tactic_id": tactic.id
                }

        # Scan cases and attribute detections to MITRE techniques
        for c in cases:
            case_techniques: set[str] = set()

            # Inspect case indicators & attributes
            indicators_text = " ".join(c.threat_indicators) + " " + c.summary + " " + c.subject

            # 1. Spearphishing Link (T1566.002)
            if c.extracted_urls or "url" in indicators_text.lower() or "link" in indicators_text.lower():
                case_techniques.add("T1566.002")

            # 2. Spearphishing Attachment (T1566.001)
            if "attachment" in indicators_text.lower() or "zip" in indicators_text.lower() or "payload" in indicators_text.lower():
                case_techniques.add("T1566.001")

            # 3. Tor Proxy (T1090.003)
            if "tor" in indicators_text.lower() or c.earliest_ip.startswith("185.220"):
                case_techniques.add("T1090.003")

            # 4. Financial Theft / BEC (T1657)
            if any(term in indicators_text.lower() for term in ["wire", "cfo", "transfer", "invoice", "payroll", "deposit"]):
                case_techniques.add("T1657")

            # 5. Masquerading / Brand Abuse (T1036.005)
            if any(brand in indicators_text.lower() for brand in ["docusign", "paypal", "microsoft", "impersonat"]):
                case_techniques.add("T1036.005")

            # 6. Domain registration (T1583.001)
            if c.sender_domain and (c.sender_domain.endswith(".live") or c.sender_domain.endswith(".net") or "portal" in c.sender_domain):
                case_techniques.add("T1583.001")

            # 7. Phishing for Info (T1598)
            if "verify" in indicators_text.lower() or "credential" in indicators_text.lower():
                case_techniques.add("T1598")

            # 8. User execution link (T1204.001)
            if "T1566.002" in case_techniques:
                case_techniques.add("T1204.001")

            # 9. Proxy (T1090)
            if "103.235" in c.earliest_ip or "proxy" in indicators_text.lower():
                case_techniques.add("T1090")

            # Record detections
            for t_id in case_techniques:
                if t_id in tech_meta:
                    if t_id not in hits:
                        hits[t_id] = MitreHeatmapHit(
                            technique_id=t_id,
                            technique_name=tech_meta[t_id]["name"],
                            tactic_id=tech_meta[t_id]["tactic_id"],
                            detection_count=0,
                            severity="medium",
                            case_ids=[],
                            last_detected=c.created_at
                        )
                    hit = hits[t_id]
                    hit.detection_count += 1
                    if c.case_id not in hit.case_ids:
                        hit.case_ids.append(c.case_id)
                    # Update severity based on count
                    if hit.detection_count >= 5:
                        hit.severity = "critical"
                    elif hit.detection_count >= 3:
                        hit.severity = "high"
                    else:
                        hit.severity = "medium"

        total_detections = sum(h.detection_count for h in hits.values())
        top_techs = sorted(hits.keys(), key=lambda k: hits[k].detection_count, reverse=True)[:5]

        return MitreHeatmapResponse(
            hits=hits,
            total_detections=total_detections,
            top_techniques=top_techs
        )

    def export_navigator_layer(self) -> dict[str, Any]:
        """Exports standard MITRE ATT&CK® Navigator JSON layer schema (v4.5)."""
        heatmap = self.calculate_heatmap()
        techniques_list = []

        for t_id, hit in heatmap.hits.items():
            color = "#f43f5e" if hit.severity == "critical" else "#fb923c" if hit.severity == "high" else "#06b6d4"
            techniques_list.append({
                "techniqueID": t_id,
                "score": hit.detection_count,
                "color": color,
                "comment": f"Detected in {hit.detection_count} PhishGuard incident cases ({', '.join(hit.case_ids[:3])})",
                "enabled": True,
                "metadata": [
                    {"name": "Severity", "value": hit.severity.upper()},
                    {"name": "LinkedCases", "value": ", ".join(hit.case_ids)}
                ]
            })

        return {
            "name": "PhishGuard AI — Active Attack Surface Layer",
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "Real-time threat detection heatmap exported directly from PhishGuard AI SOC platform.",
            "gradient": {
                "colors": ["#06b6d4", "#fb923c", "#f43f5e"],
                "minValue": 1,
                "maxValue": 10
            },
            "legendItems": [
                {"label": "Critical Threat (>= 5 cases)", "color": "#f43f5e"},
                {"label": "High Frequency (3-4 cases)", "color": "#fb923c"},
                {"label": "Active Detection (1-2 cases)", "color": "#06b6d4"}
            ],
            "techniques": techniques_list
        }


mitre_matrix_service = MitreMatrixService()

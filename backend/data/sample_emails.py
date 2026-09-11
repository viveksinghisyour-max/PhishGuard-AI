"""
Preset Benchmark RFC 822 Email Payloads for SOC Triage and Testing.
These samples represent standard simulated incident vectors for validating
forensic parsers, authentication matrices, and SMTP hop tracers.
"""

SAMPLE_EMAILS = [
    {
        "id": "sample-bec",
        "title": "CEO Wire Transfer Redirection (BEC Simulation)",
        "type": "Executive Impersonation",
        "severity": "Critical",
        "description": "Simulated Executive Wire Fraud attempt with unaligned Return-Path, urgent financial request, and SPF failure.",
        "raw_text": """Received: from mail.attacker-relay.de (185.220.101.44) by mx.enterprise-gateway.com (198.51.100.22) with ESMTP id m49219; Wed, 09 Sep 2026 13:40:02 +0000
Received: from client-node-4.local (10.240.0.12) by mail.attacker-relay.de (185.220.101.44) with ASMTP id a9811; Wed, 09 Sep 2026 13:38:15 +0000
Authentication-Results: mx.enterprise-gateway.com; spf=fail (sender IP 185.220.101.44 is not designated as permitted sender) smtp.mailfrom=bounce-handler@corporate-accts-wire.com; dkim=none; dmarc=fail action=none header.from=corporate-accts-wire.com
Received-SPF: fail (mx.enterprise-gateway.com: domain of corporate-accts-wire.com does not designate 185.220.101.44 as permitted sender)
From: "Alex Vance (Chief Executive Officer)" <cfo-exec@corporate-accts-wire.com>
To: finance-dept@phishguardai.com
Reply-To: executive-secure-drop@offshore-transfers.net
Return-Path: <bounce-handler@corporate-accts-wire.com>
Subject: URGENT: Outstanding Vendor Invoice Wire Transfer #INV-9921
Date: Wed, 09 Sep 2026 13:38:10 +0000
Message-ID: <20260909133810.9921@corporate-accts-wire.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Team,

Please process an immediate wire transfer for the outstanding invoice #INV-9921 totaling $48,250.00.
Due to our current European expansion closing today, this requires immediate action within 24 hours to prevent contractual breach.

Updated banking details for the beneficiary:
Bank: International Commercial Settlement Bank
Beneficiary: Global Trade Logistics LLC
SWIFT: ICSBDEFFXXX
Account: 9482-1049-2819-00

Confirm once the wire payment has been dispatched and reply directly with the remittance advice receipt.

Alex Vance
Chief Executive Officer
PhishGuard Global"""
    },
    {
        "id": "sample-m365",
        "title": "Microsoft 365 Password Expiration Harvester",
        "type": "Credential Theft",
        "severity": "Critical",
        "description": "Lookalike domain mimicking Microsoft identity services with fake password expiration notice and credential lure.",
        "raw_text": """Received: from smtp.bulletproof-host.ru (194.26.29.112) by mx.enterprise-gateway.com (198.51.100.22) with ESMTP id m81921; Wed, 09 Sep 2026 11:14:05 +0000
Authentication-Results: mx.enterprise-gateway.com; spf=softfail (sender IP 194.26.29.112 is not authorized) smtp.mailfrom=notifications@rnicrosoft-security-portal.xyz; dkim=fail (signature verification failed); dmarc=fail action=none header.from=rnicrosoft-security-portal.xyz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=rnicrosoft-security-portal.xyz; s=selector1; h=from:to:subject:date; bh=invalidhash==; b=fakeSignature==
From: "Microsoft 365 Security Team" <no-reply@rnicrosoft-security-portal.xyz>
To: user.account@phishguardai.com
Subject: Action Required: Microsoft 365 Password Expiration in 24 Hours
Date: Wed, 09 Sep 2026 11:12:40 +0000
Message-ID: <msg-365-alert-991204@rnicrosoft-security-portal.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<body>
  <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px;">
    <h2 style="color: #0078d4;">Microsoft 365 Identity Alert</h2>
    <p>Your organizational password for <strong>user.account@phishguardai.com</strong> will expire in 24 hours.</p>
    <p>To prevent immediate interruption of Outlook, Teams, and OneDrive access, please confirm identity and reset password below:</p>
    <p style="margin: 25px 0;">
      <a href="https://login.rnicrosoft-sec-auth.top/adfs/ls/?client_id=m365-verify" style="background: #0078d4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
        Keep Current Password & Verify Identity
      </a>
    </p>
    <p style="font-size: 11px; color: #666;">This is an automated notification. Microsoft Corporation, One Microsoft Way, Redmond, WA.</p>
  </div>
</body>
</html>"""
    },
    {
        "id": "sample-dhl",
        "title": "DHL Express Delivery Exception & Invoice Notice",
        "type": "Malware Lure",
        "severity": "Critical",
        "description": "Simulated shipping fee notice routed through Indonesian relay with direct IP URL destination.",
        "raw_text": """Received: from relay.jkt-node.id (103.145.22.89) by mx.enterprise-gateway.com (198.51.100.22) with ESMTP id dhl7712; Wed, 09 Sep 2026 08:18:22 +0000
Authentication-Results: mx.enterprise-gateway.com; spf=fail (103.145.22.89 is not an authorized DHL relay) smtp.mailfrom=dispatch@dhl-tracking-portal-notice.top; dkim=none; dmarc=fail action=none header.from=dhl-tracking-portal-notice.top
From: "DHL Express Customer Notification" <express-support@dhl-tracking-portal-notice.top>
To: logistics.department@phishguardai.com
Subject: DHL Express: Delivery Exception for Shipment #DHL-90821-US
Date: Wed, 09 Sep 2026 08:16:00 +0000
Message-ID: <dhl-exp-90821@dhl-tracking-portal-notice.top>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear Customer,

Your parcel #DHL-90821-US could not be delivered on 09/09/2026 due to an incorrect destination address and unpaid customs import clearance fees ($12.50).

Please inspect your shipping receipt and confirm payment receipt here:
http://185.220.101.5/dhl-invoice-receipt.php?shipment=DHL-90821

Failure to confirm within 48 hours will result in parcel return to sender.

Thank you for choosing DHL Express.
DHL Worldwide Network Service 2026"""
    },
    {
        "id": "sample-benign",
        "title": "Verified Corporate InfoSec Quarterly Briefing",
        "type": "Benign Corporate",
        "severity": "Low",
        "description": "Legitimate corporate email from phishguardai.com with complete SPF, DKIM, and DMARC alignment and zero threat indicators.",
        "raw_text": """Received: from mail-relay.phishguardai.com (198.51.100.22) by internal-mda.phishguardai.com with ESMTP id sec9921; Wed, 09 Sep 2026 09:00:00 +0000
Authentication-Results: internal-mda.phishguardai.com; spf=pass (sender IP 198.51.100.22 is authorized) smtp.mailfrom=security@phishguardai.com; dkim=pass header.d=phishguardai.com header.s=k1; dmarc=pass action=none header.from=phishguardai.com
Received-SPF: pass (internal-mda.phishguardai.com: domain of phishguardai.com designates 198.51.100.22 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=phishguardai.com; s=k1; h=from:to:subject:date; bh=validhash==; b=validSignature==
From: "PhishGuard InfoSec Operations" <security@phishguardai.com>
To: staff-all@phishguardai.com
Subject: Quarterly Security Update: MFA Verification & Baseline Guidelines
Date: Wed, 09 Sep 2026 09:00:00 +0000
Message-ID: <sec-2026-q3-briefing@phishguardai.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello Team,

This is our scheduled quarterly cybersecurity briefing for all staff members.
During the previous sprint, our SOC team monitored and defended against multiple simulated phishing scenarios across global gateways.

Key Best Practices:
1. Verify sender domains carefully before reviewing unexpected invoice requests.
2. Report suspicious emails using the PhishGuard AI Ingestion Portal.
3. Keep multi-factor authentication (MFA) enabled on all corporate workstations.

If you have questions, please reach out to our IT Helpdesk directly via internal Slack #infosec.

Best regards,
InfoSec Operations Team
PhishGuard AI Platform"""
    }
]

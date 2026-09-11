import os
import re

from .forensics import (
    evaluate_spf_ip,
    parse_auth_headers,
    verify_dkim_cryptographic,
)

from .mime_parser import parse_mime_content


def process_eml_file(file_path: str, client_ip: str = None) -> dict:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    parsed_data = parse_mime_content(raw_bytes)

    auth_forensics = parse_auth_headers(
        parsed_data["headers"]
    )

    dkim_crypto_pass = verify_dkim_cryptographic(
        raw_bytes
    )

    # Extract clean email address for live SPF lookup if IP is supplied
    sender_raw = parsed_data["from"]

    email_match = re.search(
        r'[\w\.-]+@[\w\.-]+',
        sender_raw
    )

    sender_email = (
        email_match.group(0)
        if email_match
        else sender_raw
    )

    live_spf = None

    if client_ip and sender_email:
        domain = (
            sender_email.split("@")[-1]
            if "@" in sender_email
            else ""
        )

        live_spf = evaluate_spf_ip(
            client_ip,
            sender_email,
            domain
        )

    return {
        "metadata": {
            "message_id": parsed_data["message_id"],
            "subject": parsed_data["subject"],
            "from": parsed_data["from"],
            "to": parsed_data["to"],
            "date": parsed_data["date"],
        },

        "body": {
            "text": parsed_data["body_text"],
            "html": parsed_data["body_html"],
        },

        "attachments": [
            {
                "filename": att["filename"],
                "content_type": att["content_type"],
                "size_bytes": (
                    len(att["payload"])
                    if att["payload"]
                    else 0
                ),
            }
            for att in parsed_data["attachments"]
        ],

        "forensics": {
            "header_authentication": auth_forensics,
            "dkim_signature_valid": dkim_crypto_pass,
            "live_spf_check": live_spf,
        },
    }
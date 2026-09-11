import re

import dkim
import spf
import authres


def verify_dkim_cryptographic(raw_bytes: bytes) -> bool:
    """Cryptographically verifies DKIM signatures present in raw email bytes."""
    try:
        return dkim.verify(raw_bytes)
    except Exception:
        return False


def evaluate_spf_ip(
    client_ip: str,
    sender_email: str,
    helo_domain: str
) -> dict:
    """Executes a live SPF check using IP address and sender identity."""
    try:
        result, code, explanation = spf.check2(
            i=client_ip,
            s=sender_email,
            h=helo_domain
        )

        return {
            "spf_result": result,
            "response_code": code,
            "explanation": explanation
        }

    except Exception as e:
        return {
            "spf_result": "error",
            "error_message": str(e)
        }


def parse_auth_headers(headers: dict) -> dict:
    """Extracts SPF, DKIM, and DMARC status from existing Authentication-Results headers."""

    auth_header = headers.get("Authentication-Results", "")
    spf_header = headers.get("Received-SPF", "")

    parsed_results = {
        "spf_status": "none",
        "dkim_status": "none",
        "dmarc_status": "none",
        "raw_auth_results": auth_header
    }

    if auth_header:
        try:
            res = authres.AuthenticationResultsHeader.parse(auth_header)

            for auth_res in res.results:

                if auth_res.method == "spf":
                    parsed_results["spf_status"] = auth_res.result

                elif auth_res.method == "dkim":
                    parsed_results["dkim_status"] = auth_res.result

                elif auth_res.method == "dmarc":
                    parsed_results["dmarc_status"] = auth_res.result

        except Exception:
            # Fallback regex parsing if strict header parsing fails

            parsed_results["spf_status"] = (
                "pass" if "spf=pass" in auth_header.lower()
                else "fail/none"
            )

            parsed_results["dkim_status"] = (
                "pass" if "dkim=pass" in auth_header.lower()
                else "fail/none"
            )

            parsed_results["dmarc_status"] = (
                "pass" if "dmarc=pass" in auth_header.lower()
                else "fail/none"
            )

    if parsed_results["spf_status"] == "none" and spf_header:
        parsed_results["spf_status"] = (
            "pass" if spf_header.lower().startswith("pass")
            else "fail"
        )

    return parsed_results
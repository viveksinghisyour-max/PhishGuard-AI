import hashlib
import re

def compute_sha256(content: str | bytes) -> str:
    """Computes SHA-256 hash of text or bytes for cryptographic evidence integrity."""
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    return hashlib.sha256(content).hexdigest()

def compute_header_fingerprint(headers: dict[str, str]) -> str:
    """Computes a normalized SHA-256 fingerprint of critical email headers."""
    critical_keys = ["from", "to", "subject", "date", "message-id", "return-path"]
    normalized = []
    for k in critical_keys:
        val = headers.get(k, "")
        normalized.append(f"{k}:{val.strip().lower()}")
    payload = "|".join(normalized)
    return compute_sha256(payload)

def sanitize_text(text: str) -> str:
    """Strips control chars while preserving newlines and indentation."""
    if not text:
        return ""
    # Strip null bytes and non-printable control chars except \n \r \t
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

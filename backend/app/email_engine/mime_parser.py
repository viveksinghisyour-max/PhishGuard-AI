import email
from email.policy import default

def parse_mime_content(raw_bytes: bytes) -> dict:
    msg = email.message_from_bytes(raw_bytes, policy=default)
    
    headers = {k: v for k, v in msg.items()}
    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                attachments.append({
                    "filename": part.get_filename(),
                    "content_type": content_type,
                    "payload": part.get_payload(decode=True)
                })
            elif content_type == "text/plain" and "attachment" not in content_disposition:
                body_text += part.get_content()
            elif content_type == "text/html" and "attachment" not in content_disposition:
                body_html += part.get_content()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_text = msg.get_content()
        elif content_type == "text/html":
            body_html = msg.get_content()

    return {
        "headers": headers,
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments
    }
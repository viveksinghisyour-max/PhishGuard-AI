import email
import email.policy
import hashlib
import re
from typing import Optional
from html.parser import HTMLParser
from backend.models.schemas import ExtractedURL, ExtractedAttachment

class HTMLTextExtractor(HTMLParser):
    """Clean text extractor from HTML payloads."""
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.links = []
        self._current_tag = None

    def handle_starttag(self, tag, attrs):
        self._current_tag = tag.lower()
        if tag.lower() == 'a':
            for name, val in attrs:
                if name.lower() == 'href' and val:
                    self.links.append(val)

    def handle_endtag(self, tag):
        self._current_tag = None

    def handle_data(self, data):
        # Skip script and style content
        if self._current_tag not in ('script', 'style', 'head', 'title', 'meta'):
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)

    def get_text(self) -> str:
        return " ".join(self.text_parts)


class EmailParserService:
    """Enterprise RFC 822 / MIME Email Parser."""

    URL_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9-._~:/?#[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+',
        re.IGNORECASE
    )
    IP_IN_URL_REGEX = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?')
    SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly'}
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.iso', 
        '.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm', '.wsf', '.hta'
    }

    @staticmethod
    def parse_raw_message(raw_text: str, filename: Optional[str] = None) -> dict:
        """
        Parses an RFC 822 email string into structured headers, body text,
        extracted URLs, and attachments.
        """
        raw_bytes = raw_text.encode('utf-8', errors='replace')
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

        # Cryptographic Evidence Hashes
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        # Raw headers dictionary & fingerprint
        raw_headers = {}
        header_lines = []
        for key in msg.keys():
            values = msg.get_all(key)
            if values:
                raw_headers[key] = values if len(values) > 1 else values[0]
                for v in values:
                    header_lines.append(f"{key.lower()}:{v.strip()}")
        
        header_lines.sort()
        header_fingerprint = hashlib.sha256("\n".join(header_lines).encode('utf-8')).hexdigest()

        # Extract envelope metadata
        subject = str(msg.get('Subject', '(No Subject)'))
        from_header = str(msg.get('From', ''))
        to_header = str(msg.get('To', ''))
        reply_to_header = str(msg.get('Reply-To', ''))
        return_path_header = str(msg.get('Return-Path', ''))
        message_id = str(msg.get('Message-ID', ''))
        date_str = str(msg.get('Date', ''))

        # Extract bodies and attachments
        body_text_parts = []
        body_html_parts = []
        html_links = []
        attachments: list[ExtractedAttachment] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get_content_disposition() or '').lower()
                content_type = part.get_content_type()
                filename_part = part.get_filename()

                # Check if it's an attachment
                if content_disposition == 'attachment' or (filename_part and content_disposition != 'inline'):
                    att = EmailParserService._parse_attachment_part(part)
                    if att:
                        attachments.append(att)
                    continue

                # Body parts
                if content_type == 'text/plain':
                    try:
                        text_content = part.get_content()
                        if text_content:
                            body_text_parts.append(str(text_content))
                    except Exception:
                        pass
                elif content_type == 'text/html':
                    try:
                        html_content = part.get_content()
                        if html_content:
                            body_html_parts.append(str(html_content))
                            parser = HTMLTextExtractor()
                            parser.feed(str(html_content))
                            body_text_parts.append(parser.get_text())
                            html_links.extend(parser.links)
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if content_type == 'text/html':
                    body_html_parts.append(str(content))
                    parser = HTMLTextExtractor()
                    parser.feed(str(content))
                    body_text_parts.append(parser.get_text())
                    html_links.extend(parser.links)
                else:
                    body_text_parts.append(str(content))
            except Exception:
                body_text_parts.append(raw_text)

        full_body_text = "\n\n".join(body_text_parts).strip()
        full_body_html = "\n".join(body_html_parts).strip() if body_html_parts else None

        # Extract URLs from body text + HTML tags
        extracted_urls = EmailParserService._extract_urls(full_body_text, html_links)

        return {
            "sha256_hash": sha256_hash,
            "header_fingerprint": header_fingerprint,
            "subject": subject,
            "from_header": from_header,
            "to_header": to_header,
            "reply_to_header": reply_to_header,
            "return_path_header": return_path_header,
            "message_id": message_id,
            "date_str": date_str,
            "body_text": full_body_text,
            "body_html": full_body_html,
            "raw_headers": raw_headers,
            "raw_msg": msg,
            "extracted_urls": extracted_urls,
            "attachments": attachments,
            "filename": filename
        }

    @staticmethod
    def _parse_attachment_part(part) -> Optional[ExtractedAttachment]:
        """Extracts attachment metadata and cryptographic checksum."""
        try:
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            size_bytes = len(payload)
            sha256 = hashlib.sha256(payload).hexdigest()
            content_type = part.get_content_type()

            ext = ""
            if "." in filename:
                ext = "." + filename.rsplit(".", 1)[-1].lower()

            is_executable = ext in EmailParserService.SUSPICIOUS_EXTENSIONS
            verdict = "malicious" if is_executable else "clean"

            return ExtractedAttachment(
                filename=filename,
                size_bytes=size_bytes,
                content_type=content_type,
                is_executable=is_executable,
                sha256=sha256,
                threat_verdict=verdict
            )
        except Exception:
            return None

    @staticmethod
    def _extract_urls(text: str, html_links: list[str]) -> list[ExtractedURL]:
        """Discovers URLs, identifies IP-based addresses, shorteners, and domains."""
        found_urls = set(html_links)
        for match in EmailParserService.URL_REGEX.finditer(text):
            found_urls.add(match.group(0))

        results = []
        for url in sorted(found_urls):
            # Clean trailing punctuation
            cleaned_url = url.rstrip('.,)>]"\'')
            domain = ""
            try:
                # Extract domain
                domain_match = re.search(r'https?://([^/:\s]+)', cleaned_url, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1).lower()
            except Exception:
                pass

            is_ip_based = bool(EmailParserService.IP_IN_URL_REGEX.match(cleaned_url))
            is_shortener = domain in EmailParserService.SHORTENERS
            
            reasons = []
            if is_ip_based:
                reasons.append("Direct IP-based URL destination (bypasses DNS)")
            if is_shortener:
                reasons.append("URL shortener service hides final target")
            
            # Suspicious TLD check
            suspicious_tlds = ('.xyz', '.top', '.ru', '.su', '.click', '.loan', '.work', '.gq', '.tk', '.cf')
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                reasons.append(f"High-risk TLD detected on domain '{domain}'")

            is_suspicious = len(reasons) > 0

            results.append(ExtractedURL(
                url=cleaned_url,
                domain=domain,
                is_suspicious=is_suspicious,
                reasons=reasons,
                is_ip_based=is_ip_based,
                is_shortener=is_shortener
            ))

        return results

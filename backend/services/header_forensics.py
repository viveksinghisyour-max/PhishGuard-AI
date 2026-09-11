import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional, Tuple
from backend.core.config import settings
from backend.models.schemas import HeaderAnalysis, RelayHop, GeoLocationInfo
from backend.services.geolocation_service import geo_service

class HeaderForensicsService:
    """Forensic analyzer for email authentication headers, alignment, and SMTP hops."""

    IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')

    # Offline IP Intelligence Database for instant zero-dependency enrichment
    KNOWN_IP_INTEL = {
        "185.220.101.5": {
            "country": "Germany", "country_code": "DE", "city": "Frankfurt", "region": "Hesse",
            "lat": 50.1109, "lon": 8.6821, "isp": "Zwiebelfreunde e.V.", "asn": "AS200651",
            "is_hosting": True, "is_vpn": True, "is_tor": True
        },
        "185.220.101.44": {
            "country": "Germany", "country_code": "DE", "city": "Frankfurt", "region": "Hesse",
            "lat": 50.1109, "lon": 8.6821, "isp": "Zwiebelfreunde e.V.", "asn": "AS200651",
            "is_hosting": True, "is_vpn": True, "is_tor": True
        },
        "194.26.29.112": {
            "country": "Russia", "country_code": "RU", "city": "Saint Petersburg", "region": "Northwestern",
            "lat": 59.9343, "lon": 30.3351, "isp": "Chang Way Technologies Co.", "asn": "AS49453",
            "is_hosting": True, "is_vpn": False, "is_tor": False
        },
        "103.145.22.89": {
            "country": "Indonesia", "country_code": "ID", "city": "Jakarta", "region": "Special Capital Region",
            "lat": -6.2088, "lon": 106.8456, "isp": "PT Telkom Indonesia", "asn": "AS7713",
            "is_hosting": False, "is_vpn": False, "is_tor": False
        },
        "40.107.22.85": {
            "country": "United States", "country_code": "US", "city": "Redmond", "region": "Washington",
            "lat": 47.6740, "lon": -122.1215, "isp": "Microsoft Corporation", "asn": "AS8075",
            "is_hosting": True, "is_vpn": False, "is_tor": False
        },
        "209.85.220.41": {
            "country": "United States", "country_code": "US", "city": "Mountain View", "region": "California",
            "lat": 37.4220, "lon": -122.0841, "isp": "Google LLC", "asn": "AS15169",
            "is_hosting": True, "is_vpn": False, "is_tor": False
        },
        "54.240.27.12": {
            "country": "United States", "country_code": "US", "city": "Seattle", "region": "Washington",
            "lat": 47.6062, "lon": -122.3321, "isp": "Amazon.com, Inc.", "asn": "AS16509",
            "is_hosting": True, "is_vpn": False, "is_tor": False
        },
        "198.51.100.22": {
            "country": "United States", "country_code": "US", "city": "Ashburn", "region": "Virginia",
            "lat": 39.0438, "lon": -77.4874, "isp": "Corporate Infrastructure Gateway", "asn": "AS13335",
            "is_hosting": True, "is_vpn": False, "is_tor": False
        }
    }

    @staticmethod
    def analyze_headers(parsed_msg_dict: dict) -> HeaderAnalysis:
        """Evaluates SPF/DKIM/DMARC, envelope alignment, and anomalies."""
        raw_headers = parsed_msg_dict["raw_headers"]
        from_display, from_addr = parseaddr(parsed_msg_dict["from_header"])
        _, to_addr = parseaddr(parsed_msg_dict["to_header"])
        _, reply_to_addr = parseaddr(parsed_msg_dict["reply_to_header"])
        _, return_path_addr = parseaddr(parsed_msg_dict["return_path_header"])

        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        reply_to_domain = reply_to_addr.split('@')[-1].lower() if '@' in reply_to_addr else ''
        return_path_domain = return_path_addr.split('@')[-1].lower() if '@' in return_path_addr else ''

        anomalies = []

        # 1. Alignment Checks
        alignment_from_returnpath = True
        if return_path_domain and from_domain:
            alignment_from_returnpath = (return_path_domain == from_domain or 
                                         return_path_domain.endswith('.' + from_domain) or 
                                         from_domain.endswith('.' + return_path_domain))
            if not alignment_from_returnpath:
                anomalies.append(f"Return-Path domain mismatch ({return_path_domain} != {from_domain})")

        alignment_from_replyto = True
        if reply_to_domain and from_domain:
            alignment_from_replyto = (reply_to_domain == from_domain)
            if not alignment_from_replyto:
                anomalies.append(f"Reply-To diversion: Replies redirect to {reply_to_addr} instead of {from_domain}")

        # 2. Impersonation / Internal Domain Spoofing Checks
        for internal_domain in settings.INTERNAL_DOMAINS:
            # Check if display name claims to be from internal domain or executive
            lower_display = from_display.lower()
            if internal_domain.lower() in lower_display and internal_domain.lower() not in from_domain:
                anomalies.append(f"Internal display-name spoofing: Name claims '{internal_domain}' but domain is '{from_domain}'")
            if any(title in lower_display for title in ['ceo', 'cfo', 'director', 'president', 'wire transfer']) and internal_domain.lower() not in from_domain:
                anomalies.append(f"Executive display-name impersonation: '{from_display}' sending from external domain '{from_domain}'")

        # 3. SPF / DKIM / DMARC Authentication Results Parsing
        auth_results_str = HeaderForensicsService._get_header_value(raw_headers, 'Authentication-Results')
        received_spf_str = HeaderForensicsService._get_header_value(raw_headers, 'Received-SPF')

        spf_result, spf_details = HeaderForensicsService._parse_spf(auth_results_str, received_spf_str)
        dkim_result, dkim_details = HeaderForensicsService._parse_dkim(auth_results_str, raw_headers)
        dmarc_result, dmarc_details = HeaderForensicsService._parse_dmarc(auth_results_str)

        if spf_result in ('fail', 'softfail'):
            anomalies.append(f"SPF authentication {spf_result.upper()}: Mail sender server unauthorized")
        if dkim_result == 'fail':
            anomalies.append("DKIM cryptographic signature verification failed: Email altered in transit")
        if dmarc_result == 'fail':
            anomalies.append("DMARC policy failed: Envelope fails sender domain policy enforcement")

        return HeaderAnalysis(
            from_address=from_addr,
            from_display=from_display,
            from_domain=from_domain,
            to_address=to_addr,
            reply_to=reply_to_addr,
            reply_to_domain=reply_to_domain,
            return_path=return_path_addr,
            return_path_domain=return_path_domain,
            message_id=parsed_msg_dict["message_id"],
            subject=parsed_msg_dict["subject"],
            date=parsed_msg_dict["date_str"],
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            spf_details=spf_details,
            dkim_details=dkim_details,
            dmarc_details=dmarc_details,
            alignment_from_returnpath=alignment_from_returnpath,
            alignment_from_replyto=alignment_from_replyto,
            anomalies=anomalies
        )

    @staticmethod
    def parse_relay_hops(parsed_msg_dict: dict) -> Tuple[list[RelayHop], Optional[str], Optional[GeoLocationInfo]]:
        """
        Parses `Received:` headers chronologically from bottom (sender) to top (recipient).
        Calculates transit delays and detects the earliest reliable public origin IP.
        """
        raw_msg = parsed_msg_dict["raw_msg"]
        received_headers = raw_msg.get_all('Received') or []

        if not received_headers:
            return [], None, None

        # Chronological order: reverse the stack (bottom hop occurred first)
        chronological_hops = list(reversed(received_headers))
        hops: list[RelayHop] = []

        earliest_public_ip: Optional[str] = None
        earliest_geo: Optional[GeoLocationInfo] = None
        prev_dt: Optional[datetime] = None

        for idx, rec_text in enumerate(chronological_hops, start=1):
            from_server, by_server, hop_ip, hop_time_str = HeaderForensicsService._parse_single_received(rec_text)

            # Check if hop IP is private RFC 1918
            is_private = True
            if hop_ip:
                is_private = HeaderForensicsService._is_private_ip(hop_ip)

            # Calculate delay seconds from previous hop
            delay_seconds = 0
            if hop_time_str:
                try:
                    current_dt = parsedate_to_datetime(hop_time_str)
                    if prev_dt and current_dt >= prev_dt:
                        delay_seconds = int((current_dt - prev_dt).total_seconds())
                    prev_dt = current_dt
                except Exception:
                    pass

            # Resolve IP Geolocation
            geo_data = HeaderForensicsService.resolve_ip_geo(hop_ip) if hop_ip and not is_private else None

            # Earliest origin identification
            is_origin = False
            if not is_private and hop_ip and earliest_public_ip is None:
                is_origin = True
                earliest_public_ip = hop_ip
                earliest_geo = geo_data

            hop = RelayHop(
                hop_number=idx,
                from_server=from_server,
                by_server=by_server,
                ip=hop_ip or "N/A",
                timestamp=hop_time_str or "",
                delay_seconds=max(0, delay_seconds),
                is_private=is_private,
                is_origin=is_origin,
                country=geo_data.country if geo_data else ("Internal / Private" if is_private else "Unknown"),
                country_code=geo_data.country_code if geo_data else ("LAN" if is_private else ""),
                city=geo_data.city if geo_data else "",
                region=geo_data.region if geo_data else "",
                latitude=geo_data.latitude if geo_data else 0.0,
                longitude=geo_data.longitude if geo_data else 0.0,
                isp=geo_data.isp if geo_data else ("Private Subnet" if is_private else ""),
                asn=geo_data.asn if geo_data else "",
                is_hosting=geo_data.is_hosting if geo_data else False,
                is_vpn=geo_data.is_vpn if geo_data else False,
                is_tor=geo_data.is_tor if geo_data else False
            )
            hops.append(hop)

        return hops, earliest_public_ip, earliest_geo

    @staticmethod
    def resolve_ip_geo(ip_str: str) -> GeoLocationInfo:
        """Resolves IP metadata from GeolocationService."""
        resolved = geo_service.resolve_ip(ip_str)
        if resolved:
            return resolved

        # Fallback heuristic for other public IPs
        return GeoLocationInfo(
            ip=ip_str,
            country="International Public IPv4",
            country_code="GL",
            city="Autonomous Node",
            region="Internet Routing Gateway",
            latitude=37.751,
            longitude=-122.42,
            isp="Tier-1 Upstream Carrier",
            asn="AS0",
            is_hosting=True,
            is_vpn=False,
            is_tor=False,
            confidence="Low"
        )

    @staticmethod
    def _parse_single_received(received_str: str) -> Tuple[str, str, str, str]:
        """Extracts from, by, IP, and timestamp from a single Received header."""
        from_server = ""
        by_server = ""
        hop_ip = ""
        timestamp = ""

        # Extract timestamp after last semicolon
        if ';' in received_str:
            parts = received_str.rsplit(';', 1)
            timestamp = parts[1].strip()
            routing_part = parts[0]
        else:
            routing_part = received_str

        # Extract 'from ...'
        from_match = re.search(r'from\s+([^\s\(\)]+)', routing_part, re.IGNORECASE)
        if from_match:
            from_server = from_match.group(1).strip()

        # Extract 'by ...'
        by_match = re.search(r'by\s+([^\s\(\)]+)', routing_part, re.IGNORECASE)
        if by_match:
            by_server = by_match.group(1).strip()

        # Extract IP inside brackets/parens
        ip_matches = HeaderForensicsService.IPV4_REGEX.findall(routing_part)
        if ip_matches:
            # Usually the IP inside parentheses in 'from host (IP)' is the transmitting server
            hop_ip = ip_matches[0]

        return from_server, by_server, hop_ip, timestamp

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Determines if an IPv4 address is an RFC 1918 private / loopback IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @staticmethod
    def _get_header_value(headers: dict, key: str) -> str:
        val = headers.get(key, '')
        if isinstance(val, list):
            return " ".join(val)
        return str(val)

    @staticmethod
    def _parse_spf(auth_results: str, received_spf: str) -> Tuple[str, str]:
        combined = f"{auth_results} {received_spf}".lower()
        if 'spf=pass' in combined or 'pass (' in combined:
            return 'pass', 'SPF passed: Transmitting server is authorized in DNS SPF record'
        if 'spf=fail' in combined:
            return 'fail', 'SPF failed: Transmitting server is NOT authorized in DNS SPF record'
        if 'spf=softfail' in combined:
            return 'softfail', 'SPF softfail: Server is not formally approved (~all mechanism)'
        if 'spf=neutral' in combined:
            return 'neutral', 'SPF neutral: Domain owner specifies neither approval nor rejection'
        return 'none', 'No SPF authentication records discovered'

    @staticmethod
    def _parse_dkim(auth_results: str, raw_headers: dict) -> Tuple[str, str]:
        auth_lower = auth_results.lower()
        has_dkim_sig = 'DKIM-Signature' in raw_headers

        if 'dkim=pass' in auth_lower:
            return 'pass', 'DKIM passed: Cryptographic digital signature verified with public key'
        if 'dkim=fail' in auth_lower:
            return 'fail', 'DKIM failed: Signature verification failed (header or body tampered)'
        if has_dkim_sig:
            return 'neutral', 'DKIM signature present but unverified by recipient gateway'
        return 'none', 'No DKIM cryptographic signature discovered in email headers'

    @staticmethod
    def _parse_dmarc(auth_results: str) -> Tuple[str, str]:
        auth_lower = auth_results.lower()
        if 'dmarc=pass' in auth_lower:
            return 'pass', 'DMARC passed: SPF and DKIM alignment enforced and confirmed'
        if 'dmarc=fail' in auth_lower:
            return 'fail', 'DMARC failed: Sender envelope fails domain protection policy'
        return 'none', 'No DMARC evaluation records discovered in headers'

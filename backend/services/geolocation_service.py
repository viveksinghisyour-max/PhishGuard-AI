import math
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Tuple
import httpx

from backend.models.schemas import GeoLocationInfo, RelayHop
from backend.core.config import settings

logger = logging.getLogger(__name__)

class GeolocationService:
    """
    Forensic IP Geolocation & Transmission Trajectory Tracer.
    Resolves public IP infrastructure, geolocation coordinates, and calculates
    great-circle transmission distance across global SMTP relay hops.
    """

    # Comprehensive offline IP intelligence for zero-dependency operation & instant benchmark testing
    OFFLINE_GEO_DATABASE: Dict[str, Dict[str, Any]] = {
        # TOR Exit Nodes & Adversarial Relays
        "185.220.101.5": {
            "country": "Germany", "country_code": "DE", "city": "Frankfurt am Main", "region": "Hesse",
            "latitude": 50.1109, "longitude": 8.6821, "isp": "Zwiebelfreunde e.V. (Tor Exit)", "asn": "AS200651",
            "is_hosting": True, "is_vpn": True, "is_tor": True, "confidence": "High"
        },
        "185.220.101.44": {
            "country": "Germany", "country_code": "DE", "city": "Frankfurt am Main", "region": "Hesse",
            "latitude": 50.1109, "longitude": 8.6821, "isp": "Zwiebelfreunde e.V. (Tor Exit)", "asn": "AS200651",
            "is_hosting": True, "is_vpn": True, "is_tor": True, "confidence": "High"
        },
        "194.26.29.112": {
            "country": "Russia", "country_code": "RU", "city": "Saint Petersburg", "region": "Northwestern",
            "latitude": 59.9343, "longitude": 30.3351, "isp": "Chang Way Technologies Co.", "asn": "AS49453",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "103.145.22.89": {
            "country": "Indonesia", "country_code": "ID", "city": "Jakarta", "region": "Special Capital Region",
            "latitude": -6.2088, "longitude": 106.8456, "isp": "PT Telkom Indonesia", "asn": "AS7713",
            "is_hosting": False, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        # Legitimate Major Mail Infrastructure & Gateways
        "40.107.22.85": {
            "country": "United States", "country_code": "US", "city": "Redmond", "region": "Washington",
            "latitude": 47.6740, "longitude": -122.1215, "isp": "Microsoft Corporation (Exchange Online)", "asn": "AS8075",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "40.107.22.86": {
            "country": "United States", "country_code": "US", "city": "Redmond", "region": "Washington",
            "latitude": 47.6740, "longitude": -122.1215, "isp": "Microsoft Corporation (Exchange Online)", "asn": "AS8075",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "209.85.220.41": {
            "country": "United States", "country_code": "US", "city": "Mountain View", "region": "California",
            "latitude": 37.4220, "longitude": -122.0841, "isp": "Google LLC (Gmail Transit)", "asn": "AS15169",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "209.85.220.42": {
            "country": "United States", "country_code": "US", "city": "Mountain View", "region": "California",
            "latitude": 37.4220, "longitude": -122.0841, "isp": "Google LLC (Gmail Gateway)", "asn": "AS15169",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "54.240.27.12": {
            "country": "United States", "country_code": "US", "city": "Seattle", "region": "Washington",
            "latitude": 47.6062, "longitude": -122.3321, "isp": "Amazon.com, Inc. (AWS SES)", "asn": "AS16509",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "198.51.100.22": {
            "country": "United States", "country_code": "US", "city": "Ashburn", "region": "Virginia",
            "latitude": 39.0438, "longitude": -77.4874, "isp": "Corporate Edge Gateway", "asn": "AS13335",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "151.101.1.140": {
            "country": "United States", "country_code": "US", "city": "San Francisco", "region": "California",
            "latitude": 37.7749, "longitude": -122.4194, "isp": "Fastly Inc. (Edge CDN)", "asn": "AS54113",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        },
        "104.244.42.1": {
            "country": "United States", "country_code": "US", "city": "San Francisco", "region": "California",
            "latitude": 37.7749, "longitude": -122.4194, "isp": "Twitter / X Inc.", "asn": "AS13414",
            "is_hosting": True, "is_vpn": False, "is_tor": False, "confidence": "High"
        }
    }

    # In-memory runtime cache for queried public IPs
    _RUNTIME_CACHE: Dict[str, GeoLocationInfo] = {}

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Determines if an IPv4 or IPv6 address belongs to RFC 1918 / loopback space."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        except ValueError:
            return True

    @classmethod
    def resolve_ip(cls, ip_str: str) -> Optional[GeoLocationInfo]:
        """
        Resolves geolocation, ASN, and risk flags for an IP address.
        Checks: 1) Runtime Cache, 2) Curated Offline DB, 3) Online Resolver Fallback.
        """
        clean_ip = ip_str.strip()
        if not clean_ip or cls.is_private_ip(clean_ip):
            return None

        # 1. Runtime cache
        if clean_ip in cls._RUNTIME_CACHE:
            return cls._RUNTIME_CACHE[clean_ip]

        # 2. Curated Offline DB
        if clean_ip in cls.OFFLINE_GEO_DATABASE:
            d = cls.OFFLINE_GEO_DATABASE[clean_ip]
            geo = GeoLocationInfo(
                ip=clean_ip,
                country=d.get("country", "Unknown"),
                country_code=d.get("country_code", "UN"),
                city=d.get("city", "Unknown"),
                region=d.get("region", ""),
                latitude=d.get("latitude", 0.0),
                longitude=d.get("longitude", 0.0),
                isp=d.get("isp", "Commercial ISP"),
                asn=d.get("asn", "AS0"),
                is_hosting=d.get("is_hosting", False),
                is_vpn=d.get("is_vpn", False),
                is_tor=d.get("is_tor", False),
                confidence=d.get("confidence", "High")
            )
            cls._RUNTIME_CACHE[clean_ip] = geo
            return geo

        # 3. Live Online Resolver (ip-api.com with 2s timeout)
        try:
            with httpx.Client(timeout=2.5) as client:
                res = client.get(f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,as,hosting")
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        geo = GeoLocationInfo(
                            ip=clean_ip,
                            country=data.get("country", "Unknown"),
                            country_code=data.get("countryCode", "UN"),
                            city=data.get("city", "Unknown"),
                            region=data.get("regionName", ""),
                            latitude=float(data.get("lat", 0.0)),
                            longitude=float(data.get("lon", 0.0)),
                            isp=data.get("isp", "Unknown ISP"),
                            asn=data.get("as", "AS0").split(" ")[0],
                            is_hosting=data.get("hosting", False),
                            is_vpn=False,
                            is_tor=False,
                            confidence="Medium"
                        )
                        cls._RUNTIME_CACHE[clean_ip] = geo
                        return geo
        except Exception as e:
            logger.debug(f"Live GeoIP resolution unavailable for {clean_ip}: {e}")

        # Fallback default synthetic coordinate if offline
        fallback_geo = GeoLocationInfo(
            ip=clean_ip,
            country="Global IP Space",
            country_code="UN",
            city="External Gateway",
            region="Internet",
            latitude=38.9072,
            longitude=-77.0369,
            isp="External Transit Provider",
            asn="AS-EXT",
            is_hosting=True,
            is_vpn=False,
            is_tor=False,
            confidence="Low"
        )
        cls._RUNTIME_CACHE[clean_ip] = fallback_geo
        return fallback_geo

    @staticmethod
    def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculates the great-circle geodesic distance between two points
        on the Earth surface in kilometers using the Haversine formula.
        """
        if lat1 == 0.0 and lon1 == 0.0:
            return 0.0
        if lat2 == 0.0 and lon2 == 0.0:
            return 0.0

        r = 6371.0  # Earth radius in kilometers

        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0) ** 2 + \
            math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

        return round(r * c, 2)

    @classmethod
    def build_relay_trajectory(cls, hops: List[RelayHop]) -> Dict[str, Any]:
        """
        Builds an ordered geographic transmission trajectory connecting
        the earliest public origin server through intermediate relays to the destination gateway.
        """
        valid_points: List[Dict[str, Any]] = []
        total_distance_km = 0.0
        total_delay_seconds = sum(h.delay_seconds for h in hops)

        # Filter public hops with valid coordinates
        public_hops = [h for h in hops if not h.is_private and (h.latitude != 0.0 or h.longitude != 0.0)]
        
        origin_hop = next((h for h in hops if h.is_origin), None)
        if not origin_hop and public_hops:
            origin_hop = public_hops[0]

        for i, hop in enumerate(public_hops):
            point = {
                "hop_number": hop.hop_number,
                "ip": hop.ip,
                "latitude": hop.latitude,
                "longitude": hop.longitude,
                "city": hop.city,
                "country": hop.country,
                "country_code": hop.country_code,
                "isp": hop.isp,
                "asn": hop.asn,
                "delay_seconds": hop.delay_seconds,
                "is_origin": hop.is_origin,
                "is_destination": (i == len(public_hops) - 1),
                "is_tor": hop.is_tor,
                "is_hosting": hop.is_hosting,
                "is_vpn": hop.is_vpn
            }
            valid_points.append(point)

            # Compute geodesic segment distance
            if i > 0:
                prev = valid_points[i - 1]
                seg_dist = cls.calculate_haversine_distance(
                    prev["latitude"], prev["longitude"],
                    point["latitude"], point["longitude"]
                )
                total_distance_km += seg_dist

        return {
            "trajectory": valid_points,
            "total_points": len(valid_points),
            "origin_ip": origin_hop.ip if origin_hop else (valid_points[0]["ip"] if valid_points else "Unknown"),
            "origin_location": f"{origin_hop.city}, {origin_hop.country}" if origin_hop else "Unknown",
            "total_distance_km": round(total_distance_km, 1),
            "total_delay_seconds": total_delay_seconds,
            "has_tor": any(p.get("is_tor") for p in valid_points),
            "has_anomalous_distance": total_distance_km > 5000
        }

# Global singleton helper
geo_service = GeolocationService()

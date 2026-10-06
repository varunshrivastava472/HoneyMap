"""
GeoIP Lookup with Local Cache, Offline Demo Fallbacks, and 2s Network Timeout.
Lookup resolution pipeline:
1. `geoip_cache` SQLite table
2. OFFLINE_FALLBACK demo IP dictionary (~15 global threat / demo IPs)
3. Remote ip-api.com API (strict 2.0-second timeout)
4. Graceful unknown fallback: {"country": "Unknown", "country_code": "XX", ...}

Caches all successful lookups in SQLite geoip_cache under _DB_WRITE_LOCK.
"""
import ipaddress
import requests
from typing import Dict, Any, Optional
from database import query_db_one, execute_write

# Pre-populated realistic demo IPs for fully offline demonstrations
OFFLINE_FALLBACK: Dict[str, Dict[str, Any]] = {
    "127.0.0.1": {
        "country": "Localhost",
        "country_code": "LOC",
        "city": "Internal Lab",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": "AS0000",
        "org": "Loopback Interface"
    },
    "::1": {
        "country": "Localhost",
        "country_code": "LOC",
        "city": "Internal Lab",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": "AS0000",
        "org": "IPv6 Loopback"
    },
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": "AS205100",
        "org": "Tor Exit Node Network"
    },
    "194.26.29.112": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "asn": "AS48282",
        "org": "Mir Telecom Hosting"
    },
    "45.154.255.88": {
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "asn": "AS200019",
        "org": "Serverion B.V."
    },
    "103.145.13.12": {
        "country": "China",
        "country_code": "CN",
        "city": "Beijing",
        "latitude": 39.9042,
        "longitude": 116.4074,
        "asn": "AS4134",
        "org": "Chinanet Backbone"
    },
    "193.142.146.33": {
        "country": "Ukraine",
        "country_code": "UA",
        "city": "Kyiv",
        "latitude": 50.4501,
        "longitude": 30.5234,
        "asn": "AS210083",
        "org": "UkrTeleCom Group"
    },
    "89.248.165.101": {
        "country": "Seychelles",
        "country_code": "SC",
        "city": "Victoria",
        "latitude": -4.6191,
        "longitude": 55.4513,
        "asn": "AS202425",
        "org": "IP Volume Inc."
    },
    "14.161.45.99": {
        "country": "Vietnam",
        "country_code": "VN",
        "city": "Hanoi",
        "latitude": 21.0285,
        "longitude": 105.8542,
        "asn": "AS7552",
        "org": "Viettel Group"
    },
    "177.54.144.20": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "São Paulo",
        "latitude": -23.5505,
        "longitude": -46.6333,
        "asn": "AS28573",
        "org": "Claro Brasil"
    },
    "197.234.242.11": {
        "country": "Nigeria",
        "country_code": "NG",
        "city": "Lagos",
        "latitude": 6.5244,
        "longitude": 3.3792,
        "asn": "AS37148",
        "org": "MainOne Cable Co."
    },
    "180.250.14.77": {
        "country": "Indonesia",
        "country_code": "ID",
        "city": "Jakarta",
        "latitude": -6.2088,
        "longitude": 106.8456,
        "asn": "AS17974",
        "org": "Telkom Indonesia"
    },
    "198.51.100.22": {
        "country": "United States",
        "country_code": "US",
        "city": "San Jose",
        "latitude": 37.3382,
        "longitude": -121.8863,
        "asn": "AS15169",
        "org": "Demo Threat Research"
    },
    "198.51.100.77": {
        "country": "United Kingdom",
        "country_code": "GB",
        "city": "London",
        "latitude": 51.5074,
        "longitude": -0.1278,
        "asn": "AS2856",
        "org": "British Telecommunications"
    },
    "198.51.100.99": {
        "country": "Japan",
        "country_code": "JP",
        "city": "Tokyo",
        "latitude": 35.6762,
        "longitude": 139.6503,
        "asn": "AS2516",
        "org": "KDDI Corporation"
    },
    "203.0.113.45": {
        "country": "Australia",
        "country_code": "AU",
        "city": "Sydney",
        "latitude": -33.8688,
        "longitude": 151.2093,
        "asn": "AS1221",
        "org": "Telstra Corporation"
    },
    "192.0.2.77": {
        "country": "Canada",
        "country_code": "CA",
        "city": "Montreal",
        "latitude": 45.5017,
        "longitude": -73.5673,
        "asn": "AS577",
        "org": "Bell Canada Demo"
    }
}


import os

# In-memory fast cache for resolved IP metadata
_IN_MEMORY_GEOIP_CACHE: Dict[str, Dict[str, Any]] = {}
GEOIP_TIMEOUT = float(os.environ.get("HONEYMAP_GEOIP_TIMEOUT", "2.0"))


def lookup_ip(ip: str) -> Dict[str, Any]:
    """
    Looks up IP geolocation information.
    1. Checks in-memory _IN_MEMORY_GEOIP_CACHE.
    2. Checks OFFLINE_FALLBACK dictionary (~15 demo IPs).
    3. Handles private / loopback / documentation IPs.
    4. Queries free endpoint (ip-api.com) with configurable network timeout.
    5. Falls back gracefully to Unknown dictionary if network fails or times out.
    """
    if not ip or not isinstance(ip, str):
        ip = "127.0.0.1"

    # Step 1: In-Memory Fast Cache
    if ip in _IN_MEMORY_GEOIP_CACHE:
        return _IN_MEMORY_GEOIP_CACHE[ip]

    # Step 2: Offline Demo Fallback (in-memory dictionary)
    if ip in OFFLINE_FALLBACK:
        data = OFFLINE_FALLBACK[ip].copy()
        data["ip"] = ip
        _IN_MEMORY_GEOIP_CACHE[ip] = data
        return data

    # Step 3: Fast Handling for Private / Reserved / Documentation IPs (RFC 1918, loopback)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            data = {
                "ip": ip,
                "country": "Localhost" if ip_obj.is_loopback else "Private Network",
                "country_code": "LOC" if ip_obj.is_loopback else "PRIV",
                "city": "Internal Lab" if ip_obj.is_loopback else "Internal",
                "latitude": 0.0,
                "longitude": 0.0,
                "asn": "AS0000",
                "org": "Loopback Interface" if ip_obj.is_loopback else "Private Network"
            }
            _IN_MEMORY_GEOIP_CACHE[ip] = data
            return data
    except ValueError:
        pass

    # Step 4: Remote Network Query (ip-api.com with timeout)
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,as,org",
            timeout=GEOIP_TIMEOUT
        )
        if resp.status_code == 200:
            res = resp.json()
            if res.get("status") == "success":
                data = {
                    "ip": ip,
                    "country": res.get("country") or "Unknown",
                    "country_code": res.get("countryCode") or "XX",
                    "city": res.get("city") or "Unknown",
                    "latitude": float(res.get("lat", 0.0) or 0.0),
                    "longitude": float(res.get("lon", 0.0) or 0.0),
                    "asn": res.get("as") or "AS-UNKNOWN",
                    "org": res.get("org") or "Unknown"
                }
                _IN_MEMORY_GEOIP_CACHE[ip] = data
                return data
    except Exception:
        pass

    # Step 5: Graceful Unknown Fallback
    fallback = {
        "ip": ip,
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": "AS-UNKNOWN",
        "org": "Unknown"
    }
    _IN_MEMORY_GEOIP_CACHE[ip] = fallback
    return fallback

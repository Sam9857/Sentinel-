"""
geo_service.py — IP → location for the threat map and threat table.

Resolution order
  1. IPinfo / IPQS result if a key is configured and the IP is public
     (cached 24h; at most MAX_REMOTE_PER_CALL new lookups per request)
  2. Deterministic *simulated* location  (source = "simulated")
     Used for private / documentation ranges (10.x, 192.168.x, 203.0.113.x …)
     which have no real geography, and as a fallback when no key is set.

Every record carries `source` so the UI can label simulated geography honestly.
"""
import hashlib
import ipaddress
from concurrent.futures import ThreadPoolExecutor

from . import cache, providers, settings

MAX_REMOTE_PER_CALL = 12

# (name, ISO code, lat, lon, city)  — origin pool for simulated geography
COUNTRIES = [
    ("Russia", "RU", 55.7558, 37.6173, "Moscow"),
    ("China", "CN", 39.9042, 116.4074, "Beijing"),
    ("United States", "US", 38.9072, -77.0369, "Ashburn"),
    ("Brazil", "BR", -23.5505, -46.6333, "São Paulo"),
    ("Germany", "DE", 50.1109, 8.6821, "Frankfurt"),
    ("Netherlands", "NL", 52.3676, 4.9041, "Amsterdam"),
    ("Iran", "IR", 35.6892, 51.3890, "Tehran"),
    ("Ukraine", "UA", 50.4501, 30.5234, "Kyiv"),
    ("Vietnam", "VN", 21.0278, 105.8342, "Hanoi"),
    ("Nigeria", "NG", 6.5244, 3.3792, "Lagos"),
    ("Turkey", "TR", 41.0082, 28.9784, "Istanbul"),
    ("Indonesia", "ID", -6.2088, 106.8456, "Jakarta"),
    ("France", "FR", 48.8566, 2.3522, "Paris"),
    ("United Kingdom", "GB", 51.5074, -0.1278, "London"),
    ("Singapore", "SG", 1.3521, 103.8198, "Singapore"),
    ("South Korea", "KR", 37.5665, 126.9780, "Seoul"),
    ("Romania", "RO", 44.4268, 26.1025, "Bucharest"),
    ("Pakistan", "PK", 24.8607, 67.0011, "Karachi"),
    ("Egypt", "EG", 30.0444, 31.2357, "Cairo"),
    ("Argentina", "AR", -34.6037, -58.3816, "Buenos Aires"),
    ("South Africa", "ZA", -26.2041, 28.0473, "Johannesburg"),
    ("Poland", "PL", 52.2297, 21.0122, "Warsaw"),
    ("Hong Kong", "HK", 22.3193, 114.1694, "Hong Kong"),
    ("Australia", "AU", -33.8688, 151.2093, "Sydney"),
]
_BY_CC = {c[1]: c for c in COUNTRIES}

# Weighted so the simulated map looks like a believable origin distribution.
_WEIGHTS = [10, 10, 9, 5, 6, 6, 5, 5, 4, 3, 3, 3, 3, 3, 4, 3, 3, 3, 2, 2, 2, 2, 3, 2]

# Simulated network owners (clearly generic — not real assignments)
_SIM_NETWORKS = [
    ("AS64496", "Example Transit Ltd"), ("AS64497", "Sample Hosting GmbH"),
    ("AS64498", "Demo Broadband Co"), ("AS64499", "Placeholder Cloud Inc"),
    ("AS64500", "Test Carrier Network"), ("AS64501", "Lab Telecom"),
]


def parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_non_routable(ip: str) -> bool:
    a = parse_ip(ip)
    return (a is None) or a.is_private or a.is_reserved or a.is_loopback or a.is_link_local or a.is_multicast


def _h(ip: str, salt: str = "") -> int:
    return int(hashlib.sha256((salt + ip).encode()).hexdigest()[:12], 16)


def simulated_geo(ip: str) -> dict:
    """Deterministic: same IP → same place. Subnet-stable so /24s cluster."""
    # Group by /28-sized blocks so one test network spreads over many origins
    if "." in ip:
        a = ip.split(".")
        prefix = ".".join(a[:3]) + "/" + str(int(a[3]) // 16 if a[3].isdigit() else 0)
    else:
        prefix = ip
    idx = _h(prefix, "geo") % sum(_WEIGHTS)
    acc = 0
    chosen = COUNTRIES[0]
    for c, w in zip(COUNTRIES, _WEIGHTS):
        acc += w
        if idx < acc:
            chosen = c
            break
    j = _h(ip, "jit")
    lat = chosen[2] + ((j % 1000) / 1000 - 0.5) * 2.4
    lon = chosen[3] + (((j // 1000) % 1000) / 1000 - 0.5) * 3.2
    return {"country": chosen[0], "country_code": chosen[1], "city": chosen[4],
            "lat": round(lat, 4), "lon": round(lon, 4), "source": "simulated"}


def simulated_network(ip: str) -> dict:
    asn, org = _SIM_NETWORKS[_h(ip, "asn") % len(_SIM_NETWORKS)]
    return {"asn": asn, "isp": org, "org": org, "source": "simulated"}


def _from_provider(ip: str):
    for fn, ck in ((providers.ipinfo_lookup, f"ipinfo:{ip}"), (providers.ipqs_lookup, f"ipqs:{ip}")):
        res = cache.peek(ck) or fn(ip)
        d = res.get("data", {}) if res.get("status") == "ok" else {}
        if d.get("lat") is not None and d.get("lon") is not None:
            cc = d.get("country_code") or ""
            name = _BY_CC.get(cc, (cc,))[0]
            return {"country": name, "country_code": cc, "city": d.get("city") or "",
                    "lat": d["lat"], "lon": d["lon"], "source": "ipinfo" if "ipinfo" in ck else "ipqs"}
    return None


def lookup_many(ips) -> dict:
    """Return {ip: geo}. Never blocks long: bounded remote lookups, simulated fallback."""
    ips = list(dict.fromkeys(ips))
    out, remote = {}, []
    have_key = settings.ipinfo_key() or settings.ipqs_key()
    for ip in ips:
        cached = cache.get(f"geo:{ip}")
        if cached:
            out[ip] = cached
        elif have_key and not is_non_routable(ip) and len(remote) < MAX_REMOTE_PER_CALL:
            remote.append(ip)
        else:
            out[ip] = simulated_geo(ip)
    if remote:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for ip, geo in zip(remote, pool.map(_from_provider, remote)):
                out[ip] = cache.put(f"geo:{ip}", geo, 86400) if geo else simulated_geo(ip)
    return out

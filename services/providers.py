"""
providers.py — thin clients for external threat-intelligence APIs.

Every function:
  • reads its key from services.settings (environment) — never from the browser
  • returns a normalised dict:  {"status": ..., "message": ..., "data": {...}}
        status ∈ ok | not_configured | rate_limited | not_found | error
  • never raises

Normalising here means the dashboard never needs to know provider-specific shapes.
"""
import requests

from . import settings, cache

UA = {"User-Agent": "BitSentinel-SOC/2.0"}


def _result(status, message="", data=None):
    return {"status": status, "message": message, "data": data or {}}


def _request(method, url, *, headers=None, params=None, timeout=None):
    return requests.request(
        method, url, headers={**UA, **(headers or {})}, params=params,
        timeout=timeout or settings.http_timeout(),
    )


def _handle_http_error(resp, provider):
    if resp.status_code in (401, 403):
        return _result("error", f"{provider}: key rejected or quota exhausted (HTTP {resp.status_code})")
    if resp.status_code == 404:
        return _result("not_found", f"{provider}: no record")
    if resp.status_code == 429:
        return _result("rate_limited", f"{provider}: rate limit reached — retry shortly")
    return _result("error", f"{provider}: HTTP {resp.status_code}")


# ── VirusTotal (API v3) ──────────────────────────────────────────────────────
VT_BASE = "https://www.virustotal.com/api/v3"


def virustotal_ip(ip: str) -> dict:
    key = settings.virustotal_key()
    if not key:
        return _result("not_configured", "Set VIRUSTOTAL_API_KEY in .env")
    ck = f"vt:ip:{ip}"
    if (hit := cache.get(ck)):
        return hit
    try:
        r = _request("GET", f"{VT_BASE}/ip_addresses/{ip}", headers={"x-apikey": key})
        if r.status_code != 200:
            return _handle_http_error(r, "VirusTotal")
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        out = _result("ok", data={
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": a.get("reputation", 0),
            "country":    a.get("country"),
            "asn":        a.get("asn"),
            "as_owner":   a.get("as_owner"),
            "network":    a.get("network"),
            "tags":       a.get("tags", []),
            "link":       f"https://www.virustotal.com/gui/ip-address/{ip}",
        })
        return cache.put(ck, out, 3600)
    except requests.RequestException as e:
        return _result("error", f"VirusTotal unreachable: {type(e).__name__}")


def virustotal_file(file_hash: str) -> dict:
    key = settings.virustotal_key()
    if not key:
        return _result("not_configured", "Set VIRUSTOTAL_API_KEY in .env")
    ck = f"vt:file:{file_hash}"
    if (hit := cache.get(ck)):
        return hit
    try:
        r = _request("GET", f"{VT_BASE}/files/{file_hash}", headers={"x-apikey": key})
        if r.status_code != 200:
            return _handle_http_error(r, "VirusTotal")
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        pc = a.get("popular_threat_classification", {}) or {}
        names = [n.get("value") for n in pc.get("popular_threat_name", []) if n.get("value")]
        out = _result("ok", data={
            "md5": a.get("md5"), "sha1": a.get("sha1"), "sha256": a.get("sha256"),
            "type": a.get("type_description"),
            "name": a.get("meaningful_name") or (a.get("names") or [None])[0],
            "size": a.get("size"),
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")),
            "threat_label": pc.get("suggested_threat_label"),
            "families": names[:5],
            "first_seen": a.get("first_submission_date"),
            "last_analysis": a.get("last_analysis_date"),
            "link": f"https://www.virustotal.com/gui/file/{a.get('sha256') or file_hash}",
        })
        return cache.put(ck, out, 3600)
    except requests.RequestException as e:
        return _result("error", f"VirusTotal unreachable: {type(e).__name__}")


# ── AbuseIPDB (API v2) ───────────────────────────────────────────────────────
def abuseipdb_check(ip: str) -> dict:
    key = settings.abuseipdb_key()
    if not key:
        return _result("not_configured", "Set ABUSEIPDB_API_KEY in .env")
    ck = f"abuse:{ip}"
    if (hit := cache.get(ck)):
        return hit
    try:
        r = _request("GET", "https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": key, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90})
        if r.status_code != 200:
            return _handle_http_error(r, "AbuseIPDB")
        d = r.json().get("data", {})
        out = _result("ok", data={
            "confidence": d.get("abuseConfidenceScore", 0),
            "reports":    d.get("totalReports", 0),
            "distinct_reporters": d.get("numDistinctUsers", 0),
            "last_reported": d.get("lastReportedAt"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "tor": d.get("isTor"),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        })
        return cache.put(ck, out, 3600)
    except requests.RequestException as e:
        return _result("error", f"AbuseIPDB unreachable: {type(e).__name__}")


# ── IPinfo ───────────────────────────────────────────────────────────────────
def ipinfo_lookup(ip: str) -> dict:
    key = settings.ipinfo_key()
    if not key:
        return _result("not_configured", "Set IPINFO_API_KEY in .env")
    ck = f"ipinfo:{ip}"
    if (hit := cache.get(ck)):
        return hit
    try:
        r = _request("GET", f"https://ipinfo.io/{ip}/json", params={"token": key})
        if r.status_code != 200:
            return _handle_http_error(r, "IPinfo")
        d = r.json()
        lat = lon = None
        if d.get("loc") and "," in d["loc"]:
            lat, lon = (float(x) for x in d["loc"].split(",", 1))
        asn, _, org = (d.get("org") or "").partition(" ")
        out = _result("ok", data={
            "city": d.get("city"), "region": d.get("region"),
            "country_code": d.get("country"), "lat": lat, "lon": lon,
            "asn": asn if asn.startswith("AS") else None,
            "org": org or d.get("org"), "hostname": d.get("hostname"),
            "timezone": d.get("timezone"),
        })
        return cache.put(ck, out, 86400)
    except (requests.RequestException, ValueError) as e:
        return _result("error", f"IPinfo unreachable: {type(e).__name__}")


# ── IPQualityScore (optional: proxy / VPN / Tor flags) ───────────────────────
def ipqs_lookup(ip: str) -> dict:
    key = settings.ipqs_key()
    if not key:
        return _result("not_configured", "Set IPQS_API_KEY in .env")
    ck = f"ipqs:{ip}"
    if (hit := cache.get(ck)):
        return hit
    try:
        # IPQS places the key in the URL path by design — this call is server-side only.
        r = _request("GET", f"https://ipqualityscore.com/api/json/ip/{key}/{ip}")
        if r.status_code != 200:
            return _handle_http_error(r, "IPQualityScore")
        d = r.json()
        if not d.get("success", False):
            return _result("error", f"IPQualityScore: {d.get('message', 'request failed')}")
        out = _result("ok", data={
            "fraud_score": d.get("fraud_score", 0),
            "proxy": d.get("proxy"), "vpn": d.get("vpn"), "tor": d.get("tor"),
            "recent_abuse": d.get("recent_abuse"), "bot": d.get("bot_status"),
            "isp": d.get("ISP"), "asn": d.get("ASN"), "org": d.get("organization"),
            "country_code": d.get("country_code"), "city": d.get("city"),
            "lat": d.get("latitude"), "lon": d.get("longitude"),
        })
        return cache.put(ck, out, 3600)
    except (requests.RequestException, ValueError) as e:
        return _result("error", f"IPQualityScore unreachable: {type(e).__name__}")

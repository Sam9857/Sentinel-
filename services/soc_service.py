"""
soc_service.py — builds every payload the SOC dashboard needs.

Reads the project's existing stores (data/threats.json, blacklist, whitelist)
through the existing helpers — it does not duplicate detection logic.

Data source modes
    live  → data/threats.json  (produced by scans / live monitor)
    demo  → services.demo_data (simulated traffic through the real engine)
    auto  → live when it has >= AUTO_MIN_LIVE records, otherwise demo
"""
import json
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from models.prevention_engine import get_blacklist, is_whitelisted
from . import demo_data, geo_service, settings, cache
from .severity import LEVELS, RANK, classify, event_text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREATS_FILE = os.path.join(BASE_DIR, "data", "threats.json")
AUTO_MIN_LIVE = 25

# range → (window seconds, bucket seconds, label format)
RANGES = {
    "1H":  (3600,        300,    "%H:%M"),
    "6H":  (6 * 3600,    1800,   "%H:%M"),
    "24H": (24 * 3600,   3600,   "%H:%M"),
    "7D":  (7 * 86400,   6 * 3600, "%d %b %H:00"),
    "30D": (30 * 86400,  86400,  "%d %b"),
}


# ── Loading ──────────────────────────────────────────────────────────────────
def _parse_ts(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def _live_records() -> list:
    try:
        with open(THREATS_FILE, encoding="utf-8") as f:
            return json.load(f).get("threats", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def load(source: str = "auto"):
    """Return (records, resolved_source). Records get an epoch `_t` for fast filtering."""
    live = _live_records()
    if source == "auto":
        source = "live" if len(live) >= AUTO_MIN_LIVE else "demo"
    recs = live if source == "live" else demo_data.records()
    out = []
    for r in recs:
        t = _parse_ts(r.get("timestamp", ""))
        if t is None:
            continue
        r = dict(r)
        r["_t"] = t
        out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out, source


def _blocked_set(source):
    if source == "demo":
        # Demo never reads the real blacklist. Deterministic "auto-blocked" subset:
        return None
    return {e["ip"] for e in get_blacklist().get("blocked_ips", [])}


def _demo_blocked(ip: str, score: int) -> bool:
    """In demo mode, IPs scoring >=90 on any record are treated as auto-blocked (mirrors the 65 default threshold loosely)."""
    return score >= 95 and (hash_ip(ip) % 3 != 0)


def hash_ip(ip: str) -> int:
    return sum(ord(c) * (i + 7) for i, c in enumerate(ip))


def status_for(ip, top_score, source, blocked):
    if source == "demo":
        return "blocked" if _demo_blocked(ip, top_score) else ("investigating" if top_score >= 61 and hash_ip(ip) % 4 == 0 else "open")
    if ip in (blocked or ()):
        return "blocked"
    if is_whitelisted(ip):
        return "trusted"
    return "open"


def window(records, rng_key, now=None):
    secs, _, _ = RANGES[rng_key]
    now = now or time.time()
    cur = [r for r in records if now - secs <= r["_t"] <= now]
    prev = [r for r in records if now - 2 * secs <= r["_t"] < now - secs]
    return cur, prev


def _is_threat(r):  # anything the engine considers non-safe
    return (r.get("risk_score") or 0) >= 31


# ── Aggregation per IP ───────────────────────────────────────────────────────
def per_ip(cur, source):
    blocked = _blocked_set(source)
    groups = defaultdict(list)
    for r in cur:
        groups[r["ip"]].append(r)
    rows = []
    for ip, rs in groups.items():
        top = max(rs, key=lambda r: (r.get("risk_score") or 0, r["_t"]))
        types = Counter(t for r in rs for t in r.get("threat_types", []))
        score = top.get("risk_score") or 0
        rows.append({
            "ip": ip,
            "id": "THR-" + str(top.get("scan_id", ip)).replace("-", "")[:8].upper(),
            "score": score,
            "severity": classify(score),
            "types": [t for t, _ in types.most_common(3)],
            "events": len(rs),
            "requests": sum(r.get("request_count", 0) for r in rs),
            "first_seen": min(r["_t"] for r in rs),
            "last_seen": max(r["_t"] for r in rs),
            "status": status_for(ip, score, source, blocked),
            "source": top.get("source", "live"),
        })
    return rows


# ── Overview ─────────────────────────────────────────────────────────────────
MIN_BASELINE = 5  # don't print a % change against a near-empty previous window


def _delta(cur, prev):
    if prev < MIN_BASELINE:
        return None
    return round((cur - prev) / prev * 100, 1)


def overview(rng_key="24H", source="auto"):
    rng_key = rng_key if rng_key in RANGES else "24H"
    records, src = load(source)
    cur, prev = window(records, rng_key)
    ips = per_ip(cur, src)
    asset = settings.asset()

    threats_cur = [r for r in cur if _is_threat(r)]
    threats_prev = [r for r in window(records, rng_key)[1] if _is_threat(r)]
    crit_cur = [r for r in cur if classify(r.get("risk_score")) == "critical"]
    crit_prev = [r for r in window(records, rng_key)[1] if classify(r.get("risk_score")) == "critical"]
    alerts_cur = [r for r in cur if classify(r.get("risk_score")) in ("critical", "high")]
    alerts_prev = [r for r in window(records, rng_key)[1] if classify(r.get("risk_score")) in ("critical", "high")]

    incidents = [i for i in ips if i["score"] >= 61]
    resolved = [i for i in incidents if i["status"] in ("blocked", "trusted")]
    active = [i for i in incidents if i["status"] in ("open", "investigating")]
    suspicious = [i for i in ips if 31 <= i["score"] and i["status"] != "trusted"]

    scores = [r.get("risk_score", 0) for r in cur]
    avg = round(sum(scores) / len(scores), 1) if scores else 0

    sev = Counter(classify(r.get("risk_score")) for r in cur)
    types = Counter(t for r in cur for t in r.get("threat_types", []))

    geos = geo_service.lookup_many([i["ip"] for i in ips if i["score"] >= 31])
    countries = Counter()
    for i in ips:
        if i["score"] >= 31 and i["ip"] in geos:
            countries[(geos[i["ip"]]["country"], geos[i["ip"]]["country_code"])] += i["events"]

    from . import malware_service
    mal = malware_service.session_summary()

    return {
        "range": rng_key,
        "data_source": src,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "asset": asset,
        "geo_simulated": any(g["source"] == "simulated" for g in geos.values()),
        "kpis": {
            "total_threats":    {"value": len(threats_cur), "delta": _delta(len(threats_cur), len(threats_prev))},
            "active_threats":   {"value": len(active),   "delta": None},
            "critical":         {"value": len(crit_cur), "delta": _delta(len(crit_cur), len(crit_prev))},
            "resolved":         {"value": len(resolved), "delta": None},
            "suspicious_ips":   {"value": len(suspicious), "delta": None},
            "malware":          {"value": mal["flagged"], "delta": None, "note": f"{mal['checked']} hash lookups this session"},
            "alerts":           {"value": len(alerts_cur), "delta": _delta(len(alerts_cur), len(alerts_prev))},
            "incidents":        {"value": len(incidents), "delta": None},
        },
        "active_critical": len([i for i in active if i["severity"] == "critical"]),
        "events_total": len(cur),
        "mean_risk": avg,
        "severity": {lv: sev.get(lv, 0) for lv in LEVELS},
        "top_types": [{"type": t, "count": c} for t, c in types.most_common(6)],
        "top_countries": [{"country": k[0], "code": k[1], "count": c} for k, c in countries.most_common(6)],
        "blocked_total": len([i for i in ips if i["status"] == "blocked"]),
    }


# ── Timeline ─────────────────────────────────────────────────────────────────
def timeline(rng_key="24H", source="auto"):
    rng_key = rng_key if rng_key in RANGES else "24H"
    secs, bucket, fmt = RANGES[rng_key]
    records, src = load(source)
    now = time.time()
    start = now - secs
    n = int(secs // bucket)
    buckets = [{"t": start + (i + 1) * bucket, "events": 0, "threats": 0, "alerts": 0, "critical": 0, "requests": 0}
               for i in range(n)]
    for r in records:
        if r["_t"] < start or r["_t"] > now:
            continue
        i = min(n - 1, int((r["_t"] - start) // bucket))
        b = buckets[i]
        s = r.get("risk_score") or 0
        sv = classify(s)
        b["events"] += 1
        b["requests"] += r.get("request_count", 0)
        if s >= 31: b["threats"] += 1
        if sv in ("critical", "high"): b["alerts"] += 1
        if sv == "critical": b["critical"] += 1
    for b in buckets:
        b["label"] = datetime.fromtimestamp(b["t"]).strftime(fmt)
    return {"range": rng_key, "data_source": src, "bucket_seconds": bucket, "points": buckets}


# ── Events (live feed) ───────────────────────────────────────────────────────
def to_event(r, geo=None, source="live"):
    score = r.get("risk_score") or 0
    asset = settings.asset()
    return {
        "id": r.get("scan_id"),
        "time": r.get("timestamp"),
        "t": r.get("_t") or _parse_ts(r.get("timestamp", "")),
        "severity": classify(score),
        "score": score,
        "type": event_text(r.get("threat_types"), score),
        "threat_types": r.get("threat_types", []),
        "src_ip": r["ip"],
        "src_country": (geo or {}).get("country_code", ""),
        "destination": asset["name"],
        "status": "blocked" if (r.get("auto_block_action") or {}).get("action") == "auto_blocked" or r.get("already_blocked") else "detected",
        "source": r.get("source", source),
        "geo": geo,
    }


def events(limit=40, source="auto", min_score=0):
    records, src = load(source)
    recent = [r for r in records[-400:] if (r.get("risk_score") or 0) >= min_score][-limit:]
    geos = geo_service.lookup_many([r["ip"] for r in recent])
    return {"data_source": src, "events": [to_event(r, geos.get(r["ip"]), src) for r in reversed(recent)]}


# ── Threat table ─────────────────────────────────────────────────────────────
SORTS = {
    "severity": lambda r: (r["score"], r["last_seen"]),
    "score": lambda r: r["score"],
    "ip": lambda r: tuple(int(p) if p.isdigit() else 0 for p in r["ip"].split(".")),
    "first_seen": lambda r: r["first_seen"],
    "last_seen": lambda r: r["last_seen"],
    "country": lambda r: r.get("country", ""),
    "status": lambda r: r["status"],
    "events": lambda r: r["events"],
    "type": lambda r: (r["types"][0] if r["types"] else ""),
}


def threat_table(rng_key="24H", source="auto", q="", severity="", status="", sort="severity", direction="desc",
                 page=1, page_size=12):
    records, src = load(source)
    cur, _ = window(records, rng_key if rng_key in RANGES else "24H")
    rows = [r for r in per_ip(cur, src) if r["score"] >= 1]
    geos = geo_service.lookup_many([r["ip"] for r in rows])
    for r in rows:
        g = geos.get(r["ip"], {})
        r["country"] = g.get("country", "")
        r["country_code"] = g.get("country_code", "")
        r["geo_source"] = g.get("source", "")
        net = _network_hint(r["ip"], src)
        r.update(net)
        r["reputation"] = _reputation_hint(r["ip"], r["score"])

    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["ip"] or ql in r["id"].lower() or ql in r["country"].lower()
                or any(ql in t.lower() for t in r["types"]) or ql in (r.get("asn") or "").lower()
                or ql in (r.get("isp") or "").lower()]
    if severity:
        want = set(severity.split(","))
        rows = [r for r in rows if r["severity"] in want]
    if status:
        want = set(status.split(","))
        rows = [r for r in rows if r["status"] in want]

    key = SORTS.get(sort, SORTS["severity"])
    rows.sort(key=key, reverse=(direction != "asc"))
    total = len(rows)
    page_size = max(5, min(int(page_size), 500))
    pages = max(1, -(-total // page_size))
    page = max(1, min(int(page), pages))
    return {"data_source": src, "total": total, "page": page, "pages": pages, "page_size": page_size,
            "rows": rows[(page - 1) * page_size: page * page_size]}


def _network_hint(ip, src):
    """ASN / ISP for table rows — from provider cache or simulated; never triggers a network call."""
    for ck in (f"ipinfo:{ip}", f"ipqs:{ip}"):
        hit = cache.peek(ck)
        if hit and hit.get("status") == "ok":
            d = hit["data"]
            return {"asn": d.get("asn"), "isp": d.get("org") or d.get("isp"), "net_source": "provider"}
    if geo_service.is_non_routable(ip):
        n = geo_service.simulated_network(ip)
        return {"asn": n["asn"], "isp": n["isp"], "net_source": "simulated"}
    return {"asn": None, "isp": None, "net_source": ""}


def _reputation_hint(ip, local_score):
    """Cached external reputation if we already looked this IP up; else the local engine score."""
    ab = cache.peek(f"abuse:{ip}")
    if ab and ab.get("status") == "ok":
        return {"value": ab["data"]["confidence"], "from": "AbuseIPDB"}
    return {"value": local_score, "from": "BitSentinel"}


# ── Map ──────────────────────────────────────────────────────────────────────
def threat_map(rng_key="24H", source="auto", limit=40):
    records, src = load(source)
    cur, _ = window(records, rng_key if rng_key in RANGES else "24H")
    rows = [r for r in per_ip(cur, src) if r["score"] >= 31]
    rows.sort(key=lambda r: (r["score"], r["last_seen"]), reverse=True)
    rows = rows[:limit]
    geos = geo_service.lookup_many([r["ip"] for r in rows])
    points = []
    for r in rows:
        g = geos[r["ip"]]
        points.append({
            "ip": r["ip"], "id": r["id"], "severity": r["severity"], "score": r["score"], "status": r["status"],
            "events": r["events"], "types": r["types"], "last_seen": r["last_seen"],
            "country": g["country"], "country_code": g["country_code"], "city": g.get("city", ""),
            "lat": g["lat"], "lon": g["lon"], "geo_source": g["source"],
        })
    return {"data_source": src, "asset": settings.asset(), "points": points,
            "simulated_geo": any(p["geo_source"] == "simulated" for p in points)}

"""
ip_intelligence_service.py — one call → one normalised IP profile.

    Dashboard  →  /api/intel/ip/<ip>  →  this module
                                           ├─ IPinfo        (geo, ASN, org)
                                           ├─ AbuseIPDB     (abuse confidence, reports)
                                           ├─ VirusTotal    (engine verdicts, reputation)
                                           ├─ IPQualityScore(proxy / VPN / Tor)  [optional]
                                           └─ local engine  (BitSentinel history + block state)
                                         → merge → intel_score → severity → JSON

Behaviour for non-routable addresses (10.x, 192.168.x, 203.0.113.x …):
no external call is made (they have no public reputation, and we don't leak
internal addresses). The response is built from the local engine plus a
clearly-flagged SIMULATED profile so the demo is complete end-to-end.
"""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from models.prevention_engine import is_blocked, is_whitelisted
from . import geo_service, providers, settings, soc_service
from .severity import classify


def local_profile(ip: str, source: str = "auto") -> dict:
    records, src = soc_service.load(source)
    mine = [r for r in records if r["ip"] == ip]
    if not mine:
        return {"events": 0, "top_score": 0, "types": [], "first_seen": None, "last_seen": None,
                "blocked": is_blocked(ip), "whitelisted": is_whitelisted(ip), "data_source": src}
    top = max(mine, key=lambda r: r.get("risk_score") or 0)
    types = sorted({t for r in mine for t in r.get("threat_types", [])})
    return {
        "events": len(mine), "top_score": top.get("risk_score") or 0, "types": types,
        "first_seen": min(r["_t"] for r in mine), "last_seen": max(r["_t"] for r in mine),
        "requests": sum(r.get("request_count", 0) for r in mine),
        "blocked": is_blocked(ip) if src == "live" else soc_service._demo_blocked(ip, top.get("risk_score") or 0),
        "whitelisted": is_whitelisted(ip), "data_source": src,
    }


def _simulated(ip: str, local: dict) -> dict:
    h = geo_service._h
    geo = geo_service.simulated_geo(ip)
    net = geo_service.simulated_network(ip)
    base = local["top_score"]
    conf = max(0, min(100, int(base * 0.9 + (h(ip, "a") % 15) - 5)))
    reports = int(conf * 1.4) + h(ip, "r") % 9 if conf > 20 else h(ip, "r") % 3
    mal = int(conf / 14) if conf > 35 else 0
    return {
        "geo": geo, "network": net,
        "abuse": {"confidence": conf, "reports": reports, "last_reported": None},
        "vt": {"malicious": mal, "suspicious": h(ip, "s") % 4 if conf > 40 else 0,
               "harmless": 60 + h(ip, "h") % 10, "undetected": 14 + h(ip, "u") % 6, "reputation": -int(conf / 3), "link": None},
        "flags": {"proxy": conf > 55 and h(ip, "p") % 2 == 0, "vpn": conf > 40 and h(ip, "v") % 3 == 0,
                  "tor": conf > 70 and h(ip, "t") % 4 == 0},
    }


def lookup(ip: str, source: str = "auto") -> dict:
    local = local_profile(ip, source)
    non_routable = geo_service.is_non_routable(ip)

    out = {
        "ip": ip,
        "mode": "simulated" if non_routable else "live",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "local": local,
        "providers": {},
        "geo": None, "network": None, "abuse": None, "vt": None,
        "flags": {"proxy": None, "vpn": None, "tor": None},
    }

    if non_routable:
        sim = _simulated(ip, local)
        out.update({k: sim[k] for k in ("geo", "network", "abuse", "vt", "flags")})
        out["providers"] = {n: {"status": "simulated", "message": "Non-routable / documentation address — no external lookup"}
                            for n in ("virustotal", "abuseipdb", "ipinfo", "ipqualityscore")}
    else:
        with ThreadPoolExecutor(max_workers=4) as pool:
            f = {
                "ipinfo": pool.submit(providers.ipinfo_lookup, ip),
                "abuseipdb": pool.submit(providers.abuseipdb_check, ip),
                "virustotal": pool.submit(providers.virustotal_ip, ip),
                "ipqualityscore": pool.submit(providers.ipqs_lookup, ip),
            }
            res = {k: v.result() for k, v in f.items()}
        out["providers"] = {k: {"status": v["status"], "message": v["message"]} for k, v in res.items()}

        info, ab, vt, qs = (res[k] for k in ("ipinfo", "abuseipdb", "virustotal", "ipqualityscore"))
        geo = None
        for src_name, r in (("ipinfo", info), ("ipqs", qs)):
            d = r["data"] if r["status"] == "ok" else {}
            if d.get("lat") is not None:
                cc = d.get("country_code") or ""
                geo = {"country": geo_service._BY_CC.get(cc, (cc,))[0], "country_code": cc, "city": d.get("city") or "",
                       "lat": d["lat"], "lon": d["lon"], "source": src_name}
                break
        out["geo"] = geo
        net = {}
        if info["status"] == "ok":
            net = {"asn": info["data"].get("asn"), "isp": info["data"].get("org"), "org": info["data"].get("org"), "source": "ipinfo"}
        elif ab["status"] == "ok":
            net = {"asn": None, "isp": ab["data"].get("isp"), "org": ab["data"].get("domain"), "source": "abuseipdb"}
        elif vt["status"] == "ok":
            net = {"asn": f"AS{vt['data'].get('asn')}" if vt["data"].get("asn") else None, "isp": vt["data"].get("as_owner"),
                   "org": vt["data"].get("as_owner"), "source": "virustotal"}
        out["network"] = net or None
        if ab["status"] == "ok":
            out["abuse"] = {"confidence": ab["data"]["confidence"], "reports": ab["data"]["reports"],
                            "last_reported": ab["data"]["last_reported"], "link": ab["data"]["link"]}
            out["flags"]["tor"] = ab["data"].get("tor")
        if vt["status"] == "ok":
            out["vt"] = vt["data"]
        if qs["status"] == "ok":
            out["flags"] = {"proxy": qs["data"].get("proxy"), "vpn": qs["data"].get("vpn"),
                            "tor": qs["data"].get("tor") if qs["data"].get("tor") is not None else out["flags"]["tor"]}

    # ── Composite score: max of the signals we actually have ───────────────
    signals = {"BitSentinel engine": local["top_score"] or None}
    if out["abuse"]:
        signals["AbuseIPDB confidence"] = out["abuse"]["confidence"]
    if out["vt"]:
        v = out["vt"]
        signals["VirusTotal engines"] = min(100, v["malicious"] * 12 + v["suspicious"] * 4)
    if not non_routable and providers_ok(out, "ipqualityscore"):
        signals["IPQS fraud score"] = qs["data"].get("fraud_score", 0)
    signals = {k: v for k, v in signals.items() if v is not None}
    score = max(signals.values()) if signals else 0
    out["intel"] = {"score": score, "severity": classify(score), "signals": signals,
                    "method": "Highest normalised score across available sources"}
    return out


def providers_ok(out, name):
    return out["providers"].get(name, {}).get("status") == "ok"

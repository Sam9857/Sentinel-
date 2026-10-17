"""
demo_data.py — clearly-labelled DEMO dataset.

Why this exists: a fresh install has an empty data/threats.json, which makes a
SOC dashboard look dead. This module generates realistic *simulated* traffic and
pushes it through the project's REAL detection pipeline
(analyze_ip_behaviour → calculate_risk_score), so every score you see in demo
mode was produced by BitSentinel's own engine — only the input traffic is
simulated. It never writes to data/threats.json and never touches the blacklist.

Records are stored as offsets (seconds before "now") and re-anchored on every
request so the demo always looks fresh.
"""
import random
import threading
import time
import uuid

from models.threat_detector import analyze_ip_behaviour
from utils.risk_scoring import calculate_risk_score, score_to_level, score_to_color
from utils.live_monitor import _build_sim_stats, _PROFILES, _PROFILE_EXTRA_TYPES

_lock = threading.Lock()
_cache: dict = {"records": None}

DEMO_DAYS = 30
DEMO_COUNT = 900


def _ip_pool(rng):
    pool = []
    for net in ("192.0.2", "198.51.100", "203.0.113"):
        pool += [f"{net}.{i}" for i in rng.sample(range(2, 250), 70)]
    return pool


def make_record(ip, profile, rng, age_seconds):
    stats = _build_sim_stats(ip, profile)
    behaviour = analyze_ip_behaviour(stats)
    for t in _PROFILE_EXTRA_TYPES.get(profile, []):
        if t not in behaviour["threat_types"]:
            behaviour["threat_types"].append(t)
    score = calculate_risk_score(behaviour)
    return {
        "ip": ip,
        "request_count": behaviour.get("request_count", 0),
        "failed_attempts": behaviour.get("failed_attempts", 0),
        "unique_paths": behaviour.get("unique_paths", 0),
        "error_rate": behaviour.get("error_rate", 0),
        "threat_types": list(behaviour.get("threat_types", [])),
        "ml_anomaly": behaviour.get("ml_anomaly", False),
        "risk_score": score,
        "risk_level": score_to_level(score),
        "risk_color": score_to_color(score),
        "scan_id": str(uuid.uuid4()),
        "source": "demo",
        "_age": age_seconds,
    }


def _build():
    rng = random.Random(20261007)
    random.seed(20261007)  # live_monitor._build_sim_stats uses the global RNG
    pool = _ip_pool(rng)
    # Attackers are persistent: a small set of "campaign" IPs recur often.
    campaign = rng.sample(pool, 28)
    names, weights = zip(*_PROFILES)
    out = []
    span = DEMO_DAYS * 86400
    for _ in range(DEMO_COUNT):
        # Bias toward recent time so short ranges (1H / 6H) are populated.
        age = int((rng.random() ** 1.15) * span)
        ip = rng.choice(campaign) if rng.random() < 0.55 else rng.choice(pool)
        profile = rng.choices(names, weights=weights, k=1)[0]
        out.append(make_record(ip, profile, rng, age))
    # Guarantee a lively last hour.
    for lo, hi, n in ((5, 3500, 16), (3500, 21600, 24)):
        for _ in range(n):
            ip = rng.choice(campaign)
            profile = rng.choices(names, weights=(14, 16, 20, 12, 12, 10, 10), k=1)[0]
            out.append(make_record(ip, profile, rng, rng.randint(lo, hi)))
    out.sort(key=lambda r: r["_age"])
    random.seed()  # restore entropy for the rest of the app
    return out


def records(now: float | None = None) -> list:
    """Chronological list (oldest → newest) with absolute ISO timestamps."""
    from datetime import datetime, timezone
    with _lock:
        if _cache["records"] is None:
            _cache["records"] = _build()
        base = _cache["records"]
    now = now or time.time()
    out = []
    for r in reversed(base):  # base is newest-first by age
        rec = {k: v for k, v in r.items() if k != "_age"}
        rec["timestamp"] = datetime.fromtimestamp(now - r["_age"], tz=timezone.utc).replace(tzinfo=None).isoformat()
        rec["whitelisted"] = False
        rec["already_blocked"] = False
        out.append(rec)
    return out


def tick() -> dict:
    """One fresh simulated event for the live feed (not persisted)."""
    from datetime import datetime, timezone
    rng = random.Random()
    base = records()
    ip = rng.choice([r["ip"] for r in base[-400:]])
    names, _ = zip(*_PROFILES)
    profile = rng.choices(names, weights=(14, 14, 22, 12, 14, 12, 12), k=1)[0]
    random_state = random.getstate()
    rec = make_record(ip, profile, rng, 0)
    random.setstate(random_state)
    rec.pop("_age", None)
    rec["timestamp"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    rec["whitelisted"] = False
    rec["already_blocked"] = False
    return rec

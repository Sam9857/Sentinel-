"""
soc_routes.py — read-only JSON API consumed by the SOC dashboard.

GET /api/soc/meta
GET /api/soc/overview?range=24H&source=auto
GET /api/soc/timeline?range=24H
GET /api/soc/events?limit=40
GET /api/soc/threats?range=&q=&severity=&status=&sort=&dir=&page=&page_size=
GET /api/soc/map?range=24H
GET /api/soc/demo/tick          (demo mode only — one simulated event)
"""
from flask import Blueprint, jsonify, request

from services import soc_service, geo_service, demo_data, settings

soc = Blueprint("soc", __name__, url_prefix="/api/soc")


def _args():
    src = request.args.get("source", "auto")
    return (request.args.get("range", "24H").upper(), src if src in ("auto", "live", "demo") else "auto")


@soc.route("/meta")
def meta():
    live = soc_service._live_records()
    return jsonify({
        "providers": settings.provider_flags(),
        "asset": settings.asset(),
        "live_records": len(live),
        "auto_min_live": soc_service.AUTO_MIN_LIVE,
        "login_required": settings.require_login(),
    })


@soc.route("/overview")
def overview():
    r, s = _args()
    return jsonify(soc_service.overview(r, s))


@soc.route("/timeline")
def timeline():
    r, s = _args()
    return jsonify(soc_service.timeline(r, s))


@soc.route("/events")
def events():
    _, s = _args()
    limit = max(1, min(int(request.args.get("limit", 40)), 200))
    return jsonify(soc_service.events(limit, s, int(request.args.get("min_score", 0))))


@soc.route("/threats")
def threats():
    r, s = _args()
    a = request.args
    try:
        page, size = int(a.get("page", 1)), int(a.get("page_size", 12))
    except ValueError:
        page, size = 1, 12
    return jsonify(soc_service.threat_table(
        r, s, q=a.get("q", "").strip()[:64], severity=a.get("severity", ""), status=a.get("status", ""),
        sort=a.get("sort", "severity"), direction=a.get("dir", "desc"), page=page, page_size=size))


@soc.route("/map")
def threat_map():
    r, s = _args()
    return jsonify(soc_service.threat_map(r, s))


@soc.route("/demo/tick")
def demo_tick():
    rec = demo_data.tick()
    geo = geo_service.lookup_many([rec["ip"]])[rec["ip"]]
    rec["_t"] = soc_service._parse_ts(rec["timestamp"])
    ev = soc_service.to_event(rec, geo, "demo")
    ev["geo"] = geo
    return jsonify(ev)

"""
intel_routes.py — threat-intelligence endpoints (server-side API keys).

GET  /api/intel/providers        which providers are configured (booleans only)
GET  /api/intel/ip/<ip>          normalised IP profile (IPinfo + AbuseIPDB + VirusTotal + IPQS + local)
GET  /api/intel/hash/<hash>      VirusTotal file lookup by MD5 / SHA-1 / SHA-256
POST /api/intel/file             multipart 'file' → hashed locally → VirusTotal lookup by SHA-256
"""
from flask import Blueprint, jsonify, request

from services import ip_intelligence_service, malware_service, settings, geo_service

intel = Blueprint("intel", __name__, url_prefix="/api/intel")

MAX_FILE = 10 * 1024 * 1024  # matches app MAX_CONTENT_LENGTH


@intel.route("/providers")
def providers_status():
    return jsonify({"providers": settings.provider_flags()})


@intel.route("/ip/<ip>")
def ip_lookup(ip):
    if geo_service.parse_ip(ip) is None:
        return jsonify({"error": "Invalid IP address"}), 400
    return jsonify(ip_intelligence_service.lookup(ip, request.args.get("source", "auto")))


@intel.route("/hash/<file_hash>")
def hash_lookup(file_hash):
    if not malware_service.valid_hash(file_hash):
        return jsonify({"error": "Provide a valid MD5, SHA-1 or SHA-256 hash"}), 400
    return jsonify(malware_service.analyse_hash(file_hash))


@intel.route("/file", methods=["POST"])
def file_lookup():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded"}), 400
    data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        return jsonify({"error": "File too large (max 10 MB)"}), 413
    local = malware_service.hash_bytes(data)
    local["filename"] = f.filename[:120]
    return jsonify(malware_service.analyse_hash(local["sha256"], local=local))

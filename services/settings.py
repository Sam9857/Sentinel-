"""
settings.py — environment-driven configuration.

Keys are read lazily (at call time) so a restart is only needed when the
.env file changes, never when code changes.
"""
import os

try:  # python-dotenv is optional; the app still works with real env vars
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except Exception:  # pragma: no cover
    pass


def _get(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


# ── Provider keys (server-side only) ─────────────────────────────────────────
def virustotal_key() -> str:  return _get("VIRUSTOTAL_API_KEY")
def abuseipdb_key() -> str:   return _get("ABUSEIPDB_API_KEY")
def ipinfo_key() -> str:      return _get("IPINFO_API_KEY")
def ipqs_key() -> str:        return _get("IPQS_API_KEY")


def provider_flags() -> dict:
    """Which providers are configured. Booleans only — never the key itself."""
    return {
        "virustotal": bool(virustotal_key()),
        "abuseipdb":  bool(abuseipdb_key()),
        "ipinfo":     bool(ipinfo_key()),
        "ipqualityscore": bool(ipqs_key()),
    }


# ── Behaviour flags ──────────────────────────────────────────────────────────
def require_login() -> bool:
    """Existing /login flow is preserved but off by default for demos."""
    return _get("SENTINEL_REQUIRE_LOGIN", "false").lower() in ("1", "true", "yes")


def admin_credentials() -> tuple:
    return _get("SENTINEL_ADMIN_USER", "admin"), _get("SENTINEL_ADMIN_PASSWORD", "admin123")


def http_timeout() -> float:
    try:
        return float(_get("SENTINEL_HTTP_TIMEOUT", "8"))
    except ValueError:
        return 8.0


# ── Monitored asset (destination end of every attack path on the map) ────────
def asset() -> dict:
    def _f(name, default):
        try:
            return float(_get(name, str(default)))
        except ValueError:
            return default
    return {
        "name": _get("SENTINEL_ASSET_NAME", "Primary gateway"),
        "city": _get("SENTINEL_ASSET_CITY", "Mumbai"),
        "country": _get("SENTINEL_ASSET_COUNTRY", "India"),
        "country_code": _get("SENTINEL_ASSET_CC", "IN"),
        "lat": _f("SENTINEL_ASSET_LAT", 19.0760),
        "lon": _f("SENTINEL_ASSET_LON", 72.8777),
    }

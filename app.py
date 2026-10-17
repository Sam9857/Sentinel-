from dotenv import load_dotenv

load_dotenv()

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import timedelta

from services import settings  # loads .env (if python-dotenv is installed)

# ── Basic Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ── Flask App Setup ──────────────────────────────────────────────────────────
app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB max upload

# ⚠️ Use strong secret key in production
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    os.urandom(32)  # safer default instead of hardcoded string
)

# Session stability settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # Set True if using HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# ── Admin credentials (env-overridable; defaults unchanged) ───────────────────
# SENTINEL_ADMIN_USER / SENTINEL_ADMIN_PASSWORD — see .env.example
ADMIN_USERNAME, ADMIN_PASSWORD = settings.admin_credentials()

# ── Auth Helper ───────────────────────────────────────────────────────────────
def is_authenticated():
    """With SENTINEL_REQUIRE_LOGIN=false (default) the SOC dashboard opens directly.
    Set it to true to restore the original login gate — the login flow itself is unchanged."""
    if not settings.require_login():
        return True
    return session.get("authenticated") is True

@app.before_request
def protect_data_endpoints():
    """When login is enabled, API + SSE endpoints require the session too (previously they were open)."""
    if settings.require_login() and (request.path.startswith("/api/") or request.path.startswith("/stream/")):
        if session.get("authenticated") is not True:
            return jsonify({"error": "Authentication required"}), 401

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    """SOC dashboard (new). The original dashboard is still available at /legacy."""
    if not is_authenticated():
        return redirect(url_for("login"))
    return render_template("soc.html", page="soc", username=session.get("username"), login_required=settings.require_login())

@app.route("/workflow")
def workflow():
    if not is_authenticated():
        return redirect(url_for("login"))
    return render_template("workflow.html", page="workflow", username=session.get("username"), login_required=settings.require_login())

@app.route("/legacy")
def legacy_dashboard():
    if not is_authenticated():
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()  # prevent session fixation
            session["authenticated"] = True
            session["username"] = username
            session.permanent = True
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Security Headers ─────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Heavy, never-changing vendor assets (d3, fonts, world map) may be cached; everything else stays no-store.
    if request.path.startswith(("/static/vendor/", "/static/data/")):
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers["Cache-Control"] = "no-store"
    return response

# ── Error Handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests"}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ── Lazy-load Blueprints ──────────────────────────────────────────────────────
def register_blueprints(app):
    blueprints = [
        ("routes.api_routes", "api"),
        ("routes.prevention_routes", "prevention"),
        ("routes.stream_routes", "stream"),
        ("routes.monitor_routes", "live_bp"),
        ("routes.soc_routes", "soc"),        # SOC dashboard data API
        ("routes.intel_routes", "intel"),    # threat-intelligence API (server-side keys)
    ]

    for module_path, bp_name in blueprints:
        try:
            module = __import__(module_path, fromlist=[bp_name])
            blueprint = getattr(module, bp_name)
            app.register_blueprint(blueprint)
            logger.info(f"Registered {bp_name}")
        except Exception as e:
            logger.error(f"Failed to register {bp_name}: {e}")

register_blueprints(app)

# ── Lazy-load Rate Limiter ────────────────────────────────────────────────────
def init_rate_limiter():
    try:
        from models.prevention_engine import get_config
        from utils.rate_limiter import limiter

        _cfg = get_config()
        limiter.update_config(
            max_requests=_cfg.get("rate_limit_max_requests", 100),
            window_seconds=_cfg.get("rate_limit_window_seconds", 60),
        )
        logger.info("Rate limiter initialized")
    except Exception as e:
        logger.warning(f"Rate limiter setup skipped: {e}")

init_rate_limiter()

# ── Lazy-load Traffic Tap ─────────────────────────────────────────────────────
def init_traffic_tap():
    try:
        import utils.traffic_tap as traffic_tap
        traffic_tap.register(app)
        logger.info("Traffic tap registered")
    except Exception as e:
        logger.warning(f"Traffic tap not registered: {e}")

init_traffic_tap()

# ── Run Flask App ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting Flask app...")

    # ❌ DO NOT use debug=True in production
    DEBUG_MODE = os.environ.get("FLASK_DEBUG", "False") == "True"

    app.run(
        debug=DEBUG_MODE,
        host="0.0.0.0",
        port=5000,
        threaded=True
    )
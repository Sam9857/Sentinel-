"""
severity.py — single source of truth for how a 0-100 risk score maps to SOC severity.

The legacy engine only knows safe / suspicious / danger (0-30 / 31-60 / 61-100).
The SOC UI refines that into five levels without changing the engine:

    90-100  critical        61-89  high        31-60  medium
     1-30   low                0   informational
"""

LEVELS = ["critical", "high", "medium", "low", "info"]
RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def classify(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 90: return "critical"
    if s >= 61: return "high"
    if s >= 31: return "medium"
    if s >= 1:  return "low"
    return "info"


# Human-readable names for the detector's threat_types strings
EVENT_TEXT = {
    "Brute Force":      "Brute-force login attempts",
    "High Frequency":   "Abnormal request volume",
    "SQL Injection":    "SQL injection payload",
    "XSS":              "Cross-site scripting attempt",
    "Path Traversal":   "Path traversal probe",
    "Auth Failure":     "Repeated authentication failures",
    "AI Anomaly":       "Behavioural anomaly",
}


def event_text(threat_types, score) -> str:
    if threat_types:
        return EVENT_TEXT.get(threat_types[0], str(threat_types[0]))
    return "Behavioural anomaly" if score and score >= 31 else "Routine traffic"

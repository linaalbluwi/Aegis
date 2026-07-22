"""
Structured security event logger.
Logs all security events to a JSON file with timestamps and metadata.
"""
import json
import os
from datetime import datetime, timezone


LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security_events.json")


def _ensure_log_dir():
    """Create the logs directory if it doesn't exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def log_event(
    event_type: str,
    severity: str,
    client_ip: str,
    details: dict,
    request_path: str = "",
    request_method: str = "",
):
    """
    Log a security event to the JSON log file.
    """
    _ensure_log_dir()

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "client_ip": client_ip,
        "request_path": request_path,
        "request_method": request_method,
        "details": details,
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def get_severity(event_type: str) -> str:
    """Map event type to severity level."""
    severity_map = {
        "SQL_INJECTION": "CRITICAL",
        "COMMAND_INJECTION": "CRITICAL",
        "PATH_TRAVERSAL": "HIGH",
        "XSS": "HIGH",
        "PII_EXPOSURE": "HIGH",
        "SENSITIVE_KEYWORD": "MEDIUM",
        "RATE_LIMIT": "LOW",
    }
    return severity_map.get(event_type, "MEDIUM")

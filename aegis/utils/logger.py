"""
Structured security event logger with rotation.
"""
import json
import os
import glob
from datetime import datetime, timezone
from aegis import config


LOG_FILE = os.path.join(config.LOG_DIR, "security_events.json")


def _ensure_log_dir():
    if not os.path.exists(config.LOG_DIR):
        os.makedirs(config.LOG_DIR)


def _rotate_if_needed():
    """Rotate log file if it exceeds max size."""
    if not os.path.exists(LOG_FILE):
        return

    size = os.path.getsize(LOG_FILE)
    if size > config.LOG_ROTATION_SIZE:
        # Remove oldest backup
        backups = sorted(glob.glob(f"{LOG_FILE}.*"))
        if len(backups) >= config.LOG_BACKUP_COUNT:
            os.remove(backups[0])

        # Rotate current file
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        os.rename(LOG_FILE, f"{LOG_FILE}.{timestamp}")


def log_event(
    event_type: str,
    severity: str,
    client_ip: str,
    details: dict,
    request_path: str = "",
    request_method: str = "",
):
    _ensure_log_dir()
    _rotate_if_needed()

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

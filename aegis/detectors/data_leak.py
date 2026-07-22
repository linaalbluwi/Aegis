"""
Sensitive data leakage detection.
"""
import re
from aegis.utils.safe_regex import safe_search

PII_PATTERNS = {
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "API_KEY": r"(?i)(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"][^'\"]+['\"]",
    "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
}

SENSITIVE_KEYWORDS = [
    "password", "secret", "private_key", "connection_string",
    "admin", "root", "internal_ip", "backup",
]


def detect_pii(text: str) -> list[dict]:
    findings = []
    for pii_type, pattern in PII_PATTERNS.items():
        matches = safe_search(pattern, text)
        for match in matches:
            findings.append({
                "type": "PII_EXPOSURE",
                "pii_type": pii_type,
                "match": match.group()[:20] + "...",
                "position": match.start(),
            })
    return findings


def detect_sensitive_keywords(text: str) -> list[dict]:
    findings = []
    for keyword in SENSITIVE_KEYWORDS:
        if keyword.lower() in text.lower():
            findings.append({
                "type": "SENSITIVE_KEYWORD",
                "keyword": keyword,
            })
    return findings

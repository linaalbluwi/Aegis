"""
Path traversal detection patterns.
"""
import re
from aegis.utils.safe_regex import safe_search

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.%2e/",
    r"%252e%252e%252f",
    r"(?i)/etc/(passwd|shadow|hosts|group)",
    r"(?i)c:\\windows\\(system32|win\.ini)",
    r"(?i)/proc/self/",
    r"(?i)/var/log/",
    r"(?i)c:\\windows\\",
    r"(?i)\x00",
    r"%00",
    r"(?i)\.htaccess",
    r"(?i)\.env",
    r"(?i)\.git/",
    r"(?i)web\.config",
    r"(?i)wp-config\.php",
    r"(?i)file:///",
    r"(?i)file%3A//",
]


def detect_path_traversal(payload: str) -> list[dict]:
    findings = []
    for pattern in PATH_TRAVERSAL_PATTERNS:
        matches = safe_search(pattern, payload)
        for match in matches:
            findings.append({
                "type": "PATH_TRAVERSAL",
                "pattern": pattern,
                "match": match.group(),
                "position": match.start(),
            })
    return findings

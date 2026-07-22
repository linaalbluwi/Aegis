"""
Path traversal detection patterns.
"""
import re

PATH_TRAVERSAL_PATTERNS = [
    # Classic directory traversal
    r"\.\./",
    r"\.\.\\",
    # Encoded traversal
    r"%2e%2e%2f",       # ../ URL encoded
    r"%2e%2e/",          # ../ partial encoded
    r"\.%2e/",           # ../ partial encoded
    r"%252e%252e%252f",  # Double URL encoded ../
    # Unicode variants
    r"\.%c0%ae\.%c0%ae/",
    r"\.%c0%ae\.%c0%ae\\",
    # Absolute paths
    r"(?i)/etc/(passwd|shadow|hosts|group)",
    r"(?i)c:\\windows\\(system32|win\.ini)",
    r"(?i)/proc/self/",
    r"(?i)/var/log/",
    # Windows paths
    r"(?i)c:\\windows\\",
    r"(?i)\\\\windows\\\\",
    # Null byte injection
    r"\x00",
    r"%00",
    # Common sensitive files
    r"(?i)\.htaccess",
    r"(?i)\.env",
    r"(?i)\.git/",
    r"(?i)web\.config",
    r"(?i)wp-config\.php",
    # File scheme
    r"(?i)file:///",
    r"(?i)file%3A//",
]


def detect_path_traversal(payload: str) -> list[dict]:
    """
    Check a string payload for path traversal patterns.
    Returns a list of findings, empty list if clean.
    """
    findings = []

    for pattern in PATH_TRAVERSAL_PATTERNS:
        matches = re.finditer(pattern, payload)
        for match in matches:
            findings.append({
                "type": "PATH_TRAVERSAL",
                "pattern": pattern,
                "match": match.group(),
                "position": match.start(),
            })

    return findings
"""
Cross-Site Scripting (XSS) detection patterns.
"""
import re
from aegis.utils.safe_regex import safe_search

XSS_PATTERNS = [
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)<script[^>]*>",
    r"(?i)\bon\w+\s*=\s*[^>]*",
    r"(?i)javascript\s*:",
    r"(?i)<iframe[^>]*>",
    r"(?i)<embed[^>]*>",
    r"(?i)<object[^>]*>",
    r"(?i)&#x?[0-9a-f]+;",
    r"(?i)\balert\s*\(",
    r"(?i)\bconfirm\s*\(",
    r"(?i)\bprompt\s*\(",
    r"(?i)\bdocument\s*\.\s*cookie\b",
    r"(?i)\beval\s*\(",
    r"(?i)\bexpression\s*\(",
    r"(?i)data\s*:\s*text/html",
    r"(?i)<svg[^>]*onload\s*=",
    r"(?i)<img[^>]*onerror\s*=",
]


def detect_xss(payload: str) -> list[dict]:
    findings = []
    for pattern in XSS_PATTERNS:
        matches = safe_search(pattern, payload)
        for match in matches:
            findings.append({
                "type": "XSS",
                "pattern": pattern,
                "match": match.group()[:50],
                "position": match.start(),
            })
    return findings

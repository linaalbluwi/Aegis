"""
Cross-Site Scripting (XSS) detection patterns.
"""
import re

XSS_PATTERNS = [
    # Script tags
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)<script[^>]*>",
    # Event handlers
    r"(?i)\bon\w+\s*=\s*[^>]*",
    # JavaScript URIs
    r"(?i)javascript\s*:",
    # Dangerous HTML
    r"(?i)<iframe[^>]*>",
    r"(?i)<embed[^>]*>",
    r"(?i)<object[^>]*>",
    # Encoded characters
    r"(?i)&#x?[0-9a-f]+;",
    # Alert/confirm/prompt
    r"(?i)\balert\s*\(",
    r"(?i)\bconfirm\s*\(",
    r"(?i)\bprompt\s*\(",
    # Document.cookie
    r"(?i)\bdocument\s*\.\s*cookie\b",
    # Eval / expression
    r"(?i)\beval\s*\(",
    r"(?i)\bexpression\s*\(",
    # Data URIs with HTML
    r"(?i)data\s*:\s*text/html",
    # SVG with scripts
    r"(?i)<svg[^>]*onload\s*=",
    # IMG error handlers
    r"(?i)<img[^>]*onerror\s*=",
]


def detect_xss(payload: str) -> list[dict]:
    """
    Check a string payload for XSS patterns.
    Returns a list of findings, empty list if clean.
    """
    findings = []

    for pattern in XSS_PATTERNS:
        matches = re.finditer(pattern, payload)
        for match in matches:
            findings.append({
                "type": "XSS",
                "pattern": pattern,
                "match": match.group()[:50],  # Truncate for safe logging
                "position": match.start(),
            })

    return findings
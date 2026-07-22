"""
Command injection detection patterns.
"""
import re
from aegis.utils.safe_regex import safe_search

CMD_INJECTION_PATTERNS = [
    r"\|\s*\w+",
    r"&&\s*\w+",
    r"\|\|\s*\w+",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"(?i)\bcat\s+/",
    r"(?i)\brm\s+-rf\b",
    r"(?i)\bwget\s+http",
    r"(?i)\bcurl\s+http",
    r"(?i)\bnc\s+-[e|l]",
    r"(?i)\b/dev/tcp/",
    r"(?i)\bchmod\s+[0-7]{3,4}",
    r"(?i)\bwhoami\b",
    r"(?i)\bid\b",
    r"(?i)\buname\s+-a\b",
    r"(?i)\bps\s+(aux|-ef)\b",
    r"(?i)\bkill\s+-9\b",
    r"(?i)\b/etc/(passwd|shadow)\b",
    r"(?i)\b/proc/self\b",
    r"(?i)\bcmd\.exe\b",
    r"(?i)\bpowershell\.exe\b",
    r">\s*/dev/\w+",
]


def detect_command_injection(payload: str) -> list[dict]:
    findings = []
    for pattern in CMD_INJECTION_PATTERNS:
        matches = safe_search(pattern, payload)
        for match in matches:
            findings.append({
                "type": "COMMAND_INJECTION",
                "pattern": pattern,
                "match": match.group(),
                "position": match.start(),
            })
    return findings

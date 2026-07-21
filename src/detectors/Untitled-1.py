"""
SQL Injection detection patterns.
"""
import re

# Common SQL injection patterns
SQLI_PATTERNS = [
    # Classic SQLi
    r"(?i)(\bUNION\s+SELECT\b)",
    r"(?i)(\bSELECT\s+.*\bFROM\b)",
    r"(?i)(\bDROP\s+TABLE\b)",
    r"(?i)(\bINSERT\s+INTO\b)",
    r"(?i)(\bDELETE\s+FROM\b)",
    r"(?i)(\bUPDATE\s+.*\bSET\b)",
    # Comment injections
    r"(?i)(--|\#|\/\*)",
    # Tautologies
    r"(?i)(\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    r"(?i)(\bOR\s+['\"]?[a-zA-Z]+['\"]?\s*=\s*['\"]?[a-zA-Z]+['\"]?)",
    # Union-based
    r"(?i)(\bUNION\s+ALL\s+SELECT\b)",
    # Time-based
    r"(?i)(\bWAITFOR\s+DELAY\b)",
    r"(?i)(\bSLEEP\s*\(\s*\d+\s*\))",
    r"(?i)(\bBENCHMARK\s*\(.*,.*\))",
    # Information schema probing
    r"(?i)(\bINFORMATION_SCHEMA\b)",
    # Hex-encoded / obfuscated
    r"(?i)(0x[0-9a-fA-F]+)",
]


def detect_sqli(payload: str) -> list[dict]:
    """
    Check a string payload for SQL injection patterns.
    Returns a list of findings, empty list if clean.
    """
    findings = []

    for pattern in SQLI_PATTERNS:
        matches = re.finditer(pattern, payload)
        for match in matches:
            findings.append({
                "type": "SQL_INJECTION",
                "pattern": pattern,
                "match": match.group(),
                "position": match.start(),
            })

    return findings
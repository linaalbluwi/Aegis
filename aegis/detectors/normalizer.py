"""
Input normalization - decode and normalize payloads before scanning.
Prevents encoding-based bypass attacks.
"""
import urllib.parse
import unicodedata
import html
import base64
import re


def _try_decode_base64(payload: str) -> str:
    """Try to decode potential base64-encoded payloads."""
    # Look for base64-like strings (alphanumeric + / + = padding)
    base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}')
    matches = base64_pattern.findall(payload)

    decoded_parts = []
    for match in matches:
        try:
            decoded = base64.b64decode(match, validate=True).decode('utf-8', errors='ignore')
            if any(c.isprintable() or c in '\n\r\t' for c in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass

    return ' '.join(decoded_parts)


def normalize(payload: str) -> str:
    """
    Normalize a payload to catch encoding-based bypasses.
    Handles: URL encoding, Unicode normalization, HTML entities, 
    double encoding, and Base64 decoding.
    """
    if not payload:
        return payload

    # URL decode (handles %27 → ', %3C → <, etc.)
    try:
        decoded = urllib.parse.unquote(payload)
    except Exception:
        decoded = payload

    # Double URL decode (handles %2527 → %27 → ')
    try:
        decoded = urllib.parse.unquote(decoded)
    except Exception:
        pass

    # HTML entity decode (handles &#x27; → ', &lt; → <, etc.)
    try:
        decoded = html.unescape(decoded)
    except Exception:
        pass

    # Unicode normalization (handles homoglyph attacks)
    try:
        decoded = unicodedata.normalize('NFKC', decoded)
    except Exception:
        pass

    # Base64 decode (handles base64-encoded payloads)
    try:
        base64_decoded = _try_decode_base64(decoded)
        if base64_decoded:
            decoded = decoded + " " + base64_decoded
    except Exception:
        pass

    return decoded

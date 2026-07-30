"""
Input normalization - decode and normalize payloads before scanning.
Prevents encoding-based bypass attacks.
"""
import urllib.parse
import unicodedata
import html


def normalize(payload: str) -> str:
    """
    Normalize a payload to catch encoding-based bypasses.
    Handles: URL encoding, Unicode normalization, HTML entities, double encoding.
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

    # Unicode normalization (handles homoglyph attacks, different encodings)
    try:
        decoded = unicodedata.normalize('NFKC', decoded)
    except Exception:
        pass

    return decoded

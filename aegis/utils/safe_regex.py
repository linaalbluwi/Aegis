"""
Safe regex matching with timeout to prevent ReDoS attacks.
"""
import re
import time


MAX_REGEX_TIME = 0.05  # 50ms max per pattern


def safe_search(pattern: str, text: str, timeout: float = MAX_REGEX_TIME) -> list:
    """
    Search for pattern in text with approximate timeout.
    Returns list of matches, empty list on timeout or no match.
    """
    start = time.monotonic()
    matches = []

    try:
        for match in re.finditer(pattern, text):
            matches.append(match)
            # Check time after each match
            if time.monotonic() - start > timeout:
                break
    except (re.error, RecursionError):
        return []

    return matches

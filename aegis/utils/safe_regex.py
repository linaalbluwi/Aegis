"""
Safe regex matching with timeout to prevent ReDoS attacks.
"""
import re
import signal
import functools
from typing import Callable


class RegexTimeout(Exception):
    """Raised when regex matching exceeds time limit."""
    pass


def _timeout_handler(signum, frame):
    raise RegexTimeout("Regex matching timed out")


def safe_search(pattern: str, text: str, timeout: float = 0.1) -> list:
    """
    Search for pattern in text with a timeout.
    Returns list of matches, empty list if timeout or no match.
    """
    # Set up alarm
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, timeout)

    try:
        matches = list(re.finditer(pattern, text))
        return matches
    except RegexTimeout:
        return []
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

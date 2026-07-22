"""
Rate limiter - blocks IPs that exceed request thresholds.
"""
import time
from collections import defaultdict
from fastapi import Request, Response
import json

# Track requests per IP
request_log = defaultdict(list)

# Config
MAX_REQUESTS = 60      # Max requests allowed
WINDOW_SECONDS = 60    # Time window in seconds
BLOCK_DURATION = 120   # How long to block (seconds)

# Track blocked IPs
blocked_ips = {}


def rate_limit(request: Request) -> Response | None:
    """
    Check if an IP has exceeded the rate limit.
    Returns a 429 Response if blocked, None if allowed.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Check if IP is currently blocked
    if client_ip in blocked_ips:
        if now < blocked_ips[client_ip]:
            print(f"[!] RATE LIMIT - Blocked IP still restricted: {client_ip}")
            return Response(
                content=json.dumps({
                    "error": "Too many requests",
                    "retry_after": int(blocked_ips[client_ip] - now),
                }),
                status_code=429,
                media_type="application/json",
            )
        else:
            # Unblock the IP
            del blocked_ips[client_ip]

    # Clean old requests outside the window
    request_log[client_ip] = [
        t for t in request_log[client_ip] if now - t < WINDOW_SECONDS
    ]

    # Add current request
    request_log[client_ip].append(now)

    # Check if over limit
    if len(request_log[client_ip]) > MAX_REQUESTS:
        blocked_ips[client_ip] = now + BLOCK_DURATION
        print(f"[!] RATE LIMIT - IP blocked for {BLOCK_DURATION}s: {client_ip}")
        return Response(
            content=json.dumps({
                "error": "Rate limit exceeded. Blocked temporarily.",
                "retry_after": BLOCK_DURATION,
            }),
            status_code=429,
            media_type="application/json",
        )

    return None  

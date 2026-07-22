"""
Rate limiter - blocks IPs that exceed request thresholds.
"""
import time
from collections import defaultdict
from fastapi import Request, Response
import json
from aegis import config

request_log = defaultdict(list)
blocked_ips = {}


def rate_limit(request: Request) -> Response | None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    if client_ip in blocked_ips:
        if now < blocked_ips[client_ip]:
            return Response(
                content=json.dumps({"error": "Too many requests"}),
                status_code=429,
                media_type="application/json",
            )
        else:
            del blocked_ips[client_ip]

    request_log[client_ip] = [
        t for t in request_log[client_ip] if now - t < config.WINDOW_SECONDS
    ]
    request_log[client_ip].append(now)

    if len(request_log[client_ip]) > config.MAX_REQUESTS:
        blocked_ips[client_ip] = now + config.BLOCK_DURATION
        return Response(
            content=json.dumps({"error": "Too many requests"}),
            status_code=429,
            media_type="application/json",
        )

    return None

"""
Input validation middleware - enforces size and content limits.
"""
from fastapi import Request, Response
import json


# Limits
MAX_BODY_SIZE = 1_000_000       # 1MB
MAX_QUERY_LENGTH = 2000         # 2KB per value
MAX_HEADER_LENGTH = 8000        # 8KB per header
MAX_HEADER_COUNT = 100
ALLOWED_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
]


def validate_request(request: Request, body: bytes) -> Response | None:
    """
    Validate request against size and content limits.
    Returns a 413/400 Response if invalid, None if OK.
    """

    # Check body size
    if len(body) > MAX_BODY_SIZE:
        return Response(
            content=json.dumps({"error": "Request body too large"}),
            status_code=413,
            media_type="application/json",
        )

    # Check query param lengths
    for key, value in request.query_params.items():
        if len(value) > MAX_QUERY_LENGTH:
            return Response(
                content=json.dumps({"error": "Query parameter too long"}),
                status_code=414,
                media_type="application/json",
            )

    # Check header count and lengths
    if len(request.headers) > MAX_HEADER_COUNT:
        return Response(
            content=json.dumps({"error": "Too many headers"}),
            status_code=400,
            media_type="application/json",
        )

    for key, value in request.headers.items():
        if len(value) > MAX_HEADER_LENGTH:
            return Response(
                content=json.dumps({"error": "Header value too long"}),
                status_code=431,
                media_type="application/json",
            )

    return None

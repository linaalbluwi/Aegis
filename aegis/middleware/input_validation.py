"""
Input validation middleware - enforces size and content limits.
"""
from fastapi import Request, Response
import json
from aegis import config


def validate_request(request: Request, body: bytes) -> Response | None:
    if len(body) > config.MAX_BODY_SIZE:
        return Response(
            content=json.dumps({"error": "Request body too large"}),
            status_code=413,
            media_type="application/json",
        )

    for key, value in request.query_params.items():
        if len(value) > config.MAX_QUERY_LENGTH:
            return Response(
                content=json.dumps({"error": "Query parameter too long"}),
                status_code=414,
                media_type="application/json",
            )

    if len(request.headers) > config.MAX_HEADER_COUNT:
        return Response(
            content=json.dumps({"error": "Too many headers"}),
            status_code=400,
            media_type="application/json",
        )

    for key, value in request.headers.items():
        if len(value) > config.MAX_HEADER_LENGTH:
            return Response(
                content=json.dumps({"error": "Header value too long"}),
                status_code=431,
                media_type="application/json",
            )

    return None

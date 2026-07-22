"""
Security headers middleware - adds protective HTTP headers to responses.
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store, max-age=0",
    "Server": "",  # Remove server header
}


class SecurityHeaders(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        for header, value in SECURITY_HEADERS.items():
            if value:
                response.headers[header] = value
            elif header in response.headers:
                del response.headers[header]

        return response

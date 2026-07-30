"""
Concrete handlers for the security chain.
"""
import time
import json
from collections import defaultdict
from fastapi import Request, Response
from aegis import config
from aegis.chain.base import Handler
from aegis.detectors.jwt_inspector import extract_jwt, inspect_jwt
from aegis.utils.logger import log_event, get_severity
from aegis.utils.metrics import metrics

request_log = defaultdict(list)
blocked_ips = {}


class RateLimitHandler(Handler):
    """Blocks requests that exceed rate limits."""

    async def handle(self, request, call_next):
        if not config.ENABLE_RATE_LIMIT:
            return await call_next()

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        if client_ip in blocked_ips:
            if now < blocked_ips[client_ip]:
                metrics.record_rate_limit(client_ip)
                return Response(
                    content=json.dumps({"error": "Too many requests"}),
                    status_code=429,
                    media_type="application/json",
                )
            del blocked_ips[client_ip]

        request_log[client_ip] = [
            t for t in request_log[client_ip] if now - t < config.WINDOW_SECONDS
        ]
        request_log[client_ip].append(now)

        if len(request_log[client_ip]) > config.MAX_REQUESTS:
            blocked_ips[client_ip] = now + config.BLOCK_DURATION
            metrics.record_rate_limit(client_ip)
            return Response(
                content=json.dumps({"error": "Too many requests"}),
                status_code=429,
                media_type="application/json",
            )

        return await call_next()


class InputValidationHandler(Handler):
    """Validates request size and content limits."""

    async def handle(self, request, call_next):
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

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

        return await call_next()


class JWTHandler(Handler):
    """Inspects JWT tokens for attacks."""

    async def handle(self, request, call_next):
        if not config.ENABLE_JWT:
            return await call_next()

        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            return await call_next()

        token = extract_jwt(auth_header)
        if not token:
            return await call_next()

        jwt_findings = inspect_jwt(token, secret=config.JWT_SECRET)
        if jwt_findings:
            for f in jwt_findings:
                log_event(
                    event_type=f["type"],
                    severity=f.get("severity", "HIGH"),
                    client_ip=request.client.host if request.client else "unknown",
                    details=f,
                    request_path=request.url.path,
                    request_method=request.method,
                )

            return Response(
                content=json.dumps({"error": "Request blocked"}),
                status_code=403,
                media_type="application/json",
            )

        return await call_next()


class DetectionHandler(Handler):
    """Runs all registered attack detectors on the request."""

    def __init__(self):
        self._detectors = []

    def register_detector(self, detector):
        """Register an attack detector."""
        self._detectors.append(detector)

    async def handle(self, request, call_next):
        findings = []

        body_text = ""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            body_text = body.decode("utf-8", errors="ignore")[:config.MAX_BODY_SCAN]

        for key, value in request.query_params.items():
            for detector in self._detectors:
                findings.extend(detector.analyze(value[:2000]))

        suspicious_headers = ["user-agent", "referer", "x-forwarded-for", "cookie"]
        for key, value in request.headers.items():
            if key.lower() in suspicious_headers:
                for detector in self._detectors:
                    findings.extend(detector.analyze(value[:1000]))

        if body_text:
            for detector in self._detectors:
                findings.extend(detector.analyze(body_text))

        if findings:
            for f in findings:
                metrics.record_attack(f.attack_type, f.severity)
                log_event(
                    event_type=f.attack_type,
                    severity=f.severity,
                    client_ip=request.client.host if request.client else "unknown",
                    details=f.__dict__,
                    request_path=request.url.path,
                    request_method=request.method,
                )

            return Response(
                content=json.dumps({"error": "Request blocked"}),
                status_code=403,
                media_type="application/json",
            )

        return await call_next()


class SecurityHeadersHandler(Handler):
    """Adds security headers to all responses."""

    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store, max-age=0",
    }

    async def handle(self, request, call_next):
        response = await call_next()
        for header, value in self.HEADERS.items():
            response.headers[header] = value
        return response

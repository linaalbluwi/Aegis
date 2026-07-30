"""
Security middleware using Chain of Responsibility pattern.
Includes circuit breaker, retry, and graceful degradation.
"""
import time
import os
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from aegis.chain.base import MiddlewareChain
from aegis.chain.handlers import (
    RateLimitHandler,
    InputValidationHandler,
    JWTHandler,
    DetectionHandler,
    SecurityHeadersHandler,
)
from aegis.detectors.base import Finding
from aegis.detectors.sqli import detect_sqli
from aegis.detectors.xss import detect_xss
from aegis.detectors.command_injection import detect_command_injection
from aegis.detectors.path_traversal import detect_path_traversal
from aegis.utils.metrics import metrics, request_duration
from aegis.utils.resilience import FailOpenGate, logger


def _convert(findings_list, attack_type, severity):
    result = []
    for f in findings_list:
        result.append(Finding(
            detector_name=attack_type.lower(),
            attack_type=attack_type,
            severity=severity,
            match=f.get("match", ""),
            position=f.get("position", 0),
            pattern=f.get("pattern", ""),
        ))
    return result


chain = MiddlewareChain()
chain.add(RateLimitHandler())
chain.add(InputValidationHandler())
chain.add(JWTHandler())

detection = DetectionHandler()

class DetectorAdapter:
    def __init__(self, name, attack_type, severity, detect_fn):
        self._name = name
        self._attack_type = attack_type
        self._severity = severity
        self._detect_fn = detect_fn

    def analyze(self, payload):
        findings = self._detect_fn(payload)
        return _convert(findings, self._attack_type, self._severity)

detection.register_detector(DetectorAdapter("sqli", "SQL_INJECTION", "CRITICAL", detect_sqli))
detection.register_detector(DetectorAdapter("xss", "XSS", "HIGH", detect_xss))
detection.register_detector(DetectorAdapter("cmdi", "COMMAND_INJECTION", "CRITICAL", detect_command_injection))
detection.register_detector(DetectorAdapter("path_traversal", "PATH_TRAVERSAL", "HIGH", detect_path_traversal))

chain.add(detection)
chain.add(SecurityHeadersHandler())

# Fail-open gate
fail_open = FailOpenGate(max_concurrent=100, degrade_after_pct=0.8)


class SecurityGate(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        start_time = time.monotonic()
        request_path = request.url.path
        request_method = request.method

        # Protect metrics endpoint
        if request_path == "/metrics":
            metrics_token = os.getenv("AEGIS_METRICS_TOKEN", "")
            if metrics_token:
                auth = request.headers.get("authorization", "")
                expected = f"Bearer {metrics_token}"
                if auth != expected:
                    return Response(
                        content='{"error": "Unauthorized"}',
                        status_code=401,
                        media_type="application/json",
                    )

        # Fail-open check
        can_check = fail_open.acquire()

        try:
            if not can_check:
                # Fail-open mode: skip security, let request through
                logger.warning(f"FAIL-OPEN: Bypassing security for {request_method} {request_path}")
                response = await call_next(request)
                metrics.record_request(request_method, request_path, response.status_code)
                return response

            async def final_handler(req):
                response = await call_next(req)
                metrics.record_request(request_method, request_path, response.status_code)
                return response

            response = await chain.execute(request, final_handler)
            return response

        except Exception as e:
            logger.error(f"Security chain error: {str(e)[:200]}")
            # On unexpected error, fail-open
            response = await call_next(request)
            metrics.record_request(request_method, request_path, response.status_code)
            return response

        finally:
            fail_open.release()
            duration = time.monotonic() - start_time
            request_duration.labels(method=request_method, endpoint=request_path).observe(duration)

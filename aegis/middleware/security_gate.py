"""
Main security middleware - inspects all incoming requests and outgoing responses.
"""
import json
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from aegis.detectors.sqli import detect_sqli
from aegis.detectors.xss import detect_xss
from aegis.detectors.command_injection import detect_command_injection
from aegis.detectors.path_traversal import detect_path_traversal
from aegis.detectors.data_leak import detect_pii, detect_sensitive_keywords
from aegis.detectors.jwt_inspector import extract_jwt, inspect_jwt
from aegis.middleware.rate_limiter import rate_limit
from aegis.middleware.input_validation import validate_request
from aegis.utils.logger import log_event, get_severity


class SecurityGate(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        request_path = request.url.path
        request_method = request.method

        # --- RATE LIMIT CHECK ---
        rate_limit_response = rate_limit(request)
        if rate_limit_response:
            log_event(
                event_type="RATE_LIMIT",
                severity=get_severity("RATE_LIMIT"),
                client_ip=client_ip,
                details={"reason": "Rate limit exceeded"},
                request_path=request_path,
                request_method=request_method,
            )
            return rate_limit_response

        # --- INPUT VALIDATION ---
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

        validation_response = validate_request(request, body)
        if validation_response:
            return validation_response

        findings = []

        # --- JWT INSPECTION ---
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            token = extract_jwt(auth_header)
            if token:
                jwt_findings = inspect_jwt(token)
                findings.extend(jwt_findings)
                for f in jwt_findings:
                    log_event(
                        event_type=f["type"],
                        severity=f.get("severity", "HIGH"),
                        client_ip=client_ip,
                        details=f,
                        request_path=request_path,
                        request_method=request_method,
                    )

        # --- INBOUND: Inspect the request ---
        # Check query parameters (truncated for safety)
        for key, value in request.query_params.items():
            safe_value = value[:2000]  # Truncate to prevent resource exhaustion
            findings.extend(detect_sqli(safe_value))
            findings.extend(detect_xss(safe_value))
            findings.extend(detect_command_injection(safe_value))
            findings.extend(detect_path_traversal(safe_value))

        # Check headers (only user-controlled ones, truncated)
        suspicious_headers = ["user-agent", "referer", "x-forwarded-for", "cookie"]
        for key, value in request.headers.items():
            if key.lower() in suspicious_headers:
                safe_value = value[:1000]
                findings.extend(detect_sqli(safe_value))
                findings.extend(detect_xss(safe_value))
                findings.extend(detect_command_injection(safe_value))
                findings.extend(detect_path_traversal(safe_value))

        # Check body (truncated)
        if body:
            body_text = body.decode("utf-8", errors="ignore")[:10_000]
            findings.extend(detect_sqli(body_text))
            findings.extend(detect_xss(body_text))
            findings.extend(detect_command_injection(body_text))
            findings.extend(detect_path_traversal(body_text))

        if findings:
            print(f"[!] BLOCKED - {len(findings)} threat(s) detected:")
            for f in findings:
                print(f"    - {f}")
                if not f.get("type", "").startswith("JWT"):
                    log_event(
                        event_type=f["type"],
                        severity=get_severity(f["type"]),
                        client_ip=client_ip,
                        details=f,
                        request_path=request_path,
                        request_method=request_method,
                    )

            return Response(
                content=json.dumps({
                    "error": "Request blocked by security gate",
                    "reason": f"Detected {len(findings)} potential threat(s)",
                }),
                status_code=403,
                media_type="application/json",
            )

        # --- OUTBOUND ---
        response = await call_next(request)

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
            if len(response_body) > 100_000:  # Don't buffer huge responses
                break

        response_text = response_body.decode("utf-8", errors="ignore")
        leak_findings = []
        leak_findings.extend(detect_pii(response_text))
        leak_findings.extend(detect_sensitive_keywords(response_text))

        if leak_findings:
            print(f"[!] DATA LEAK DETECTED in response:")
            for f in leak_findings:
                print(f"    - {f}")
                log_event(
                    event_type=f.get("type", f.get("pii_type", "DATA_LEAK")),
                    severity=get_severity(f.get("type", f.get("pii_type", "DATA_LEAK"))),
                    client_ip=client_ip,
                    details=f,
                    request_path=request_path,
                    request_method=request_method,
                )

        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

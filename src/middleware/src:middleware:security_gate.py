"""
Main security middleware - inspects all incoming requests and outgoing responses.
"""
import json
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from src.detectors.sqli import detect_sqli
from src.detectors.xss import detect_xss
from src.detectors.command_injection import detect_command_injection
from src.detectors.data_leak import detect_pii, detect_sensitive_keywords


class SecurityGate(BaseHTTPMiddleware):
    """
    Middleware that acts as a security gate for all API traffic.
    Inspects requests for attacks and responses for data leakage.
    """

    async def dispatch(self, request: Request, call_next):
        findings = []

        # --- INBOUND: Inspect the request ---
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

        # Check query parameters
        for key, value in request.query_params.items():
            findings.extend(detect_sqli(value))
            findings.extend(detect_xss(value))
            findings.extend(detect_command_injection(value))

        # Check headers
        for key, value in request.headers.items():
            findings.extend(detect_sqli(value))
            findings.extend(detect_xss(value))
            findings.extend(detect_command_injection(value))

        # Check body
        if body:
            body_text = body.decode("utf-8", errors="ignore")
            findings.extend(detect_sqli(body_text))
            findings.extend(detect_xss(body_text))
            findings.extend(detect_command_injection(body_text))

        # If attacks found in request, block it
        if findings:
            print(f"[!] BLOCKED - {len(findings)} threat(s) detected:")
            for f in findings:
                print(f"    - {f}")
            return Response(
                content=json.dumps({
                    "error": "Request blocked by security gate",
                    "reason": f"Detected {len(findings)} potential threat(s)",
                }),
                status_code=403,
                media_type="application/json",
            )

        # --- OUTBOUND: Let the request through, then inspect the response ---
        response = await call_next(request)

        # Read response body
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        # Inspect response for data leaks
        response_text = response_body.decode("utf-8", errors="ignore")
        leak_findings = []
        leak_findings.extend(detect_pii(response_text))
        leak_findings.extend(detect_sensitive_keywords(response_text))

        if leak_findings:
            print(f"[!] DATA LEAK DETECTED in response:")
            for f in leak_findings:
                print(f"    - {f}")

        # Return the original response
        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
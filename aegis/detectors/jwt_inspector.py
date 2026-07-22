"""
JWT token inspection and validation.
"""
import jwt
import re
from datetime import datetime, timezone


# Pattern to extract JWT from Authorization header
JWT_PATTERN = r"Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"


def extract_jwt(text: str) -> str | None:
    """Extract a JWT token from a string (e.g., Authorization header)."""
    match = re.search(JWT_PATTERN, text)
    if match:
        return match.group(1)
    return None


def inspect_jwt(token: str, secret: str | None = None) -> list[dict]:
    """
    Inspect a JWT token for security issues.
    Returns a list of findings, empty list if token looks safe.
    """
    findings = []

    # Check if token has 3 parts
    parts = token.split(".")
    if len(parts) != 3:
        findings.append({
            "type": "JWT_MALFORMED",
            "severity": "HIGH",
            "detail": "Token does not have 3 parts (header.payload.signature)",
        })
        return findings

    # Decode header without verification
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        findings.append({
            "type": "JWT_INVALID_HEADER",
            "severity": "HIGH",
            "detail": f"Cannot decode header: {str(e)}",
        })
        return findings

    # Check algorithm
    alg = header.get("alg", "")
    if alg == "none":
        findings.append({
            "type": "JWT_ALG_NONE",
            "severity": "CRITICAL",
            "detail": "Algorithm 'none' is dangerous - signature bypass possible",
        })
    elif alg == "HS256" and not secret:
        findings.append({
            "type": "JWT_WEAK_SECRET",
            "severity": "MEDIUM",
            "detail": "HMAC used but no secret provided for verification",
        })

    # Decode payload without verification to check claims
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        findings.append({
            "type": "JWT_INVALID_PAYLOAD",
            "severity": "HIGH",
            "detail": f"Cannot decode payload: {str(e)}",
        })
        return findings

    # Check expiration
    exp = payload.get("exp")
    if exp:
        try:
            exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                findings.append({
                    "type": "JWT_EXPIRED",
                    "severity": "HIGH",
                    "detail": f"Token expired at {exp_time.isoformat()}",
                })
        except (TypeError, ValueError, OSError):
            findings.append({
                "type": "JWT_INVALID_EXP",
                "severity": "MEDIUM",
                "detail": "Invalid expiration timestamp",
            })

    # Check not-before
    nbf = payload.get("nbf")
    if nbf:
        try:
            nbf_time = datetime.fromtimestamp(nbf, tz=timezone.utc)
            if nbf_time > datetime.now(timezone.utc):
                findings.append({
                    "type": "JWT_NOT_YET_VALID",
                    "severity": "MEDIUM",
                    "detail": f"Token not valid until {nbf_time.isoformat()}",
                })
        except (TypeError, ValueError, OSError):
            pass

    # Check issued-at (future-dated tokens are suspicious)
    iat = payload.get("iat")
    if iat:
        try:
            iat_time = datetime.fromtimestamp(iat, tz=timezone.utc)
            if iat_time > datetime.now(timezone.utc):
                findings.append({
                    "type": "JWT_FUTURE_IAT",
                    "severity": "LOW",
                    "detail": "Token issued in the future - clock skew or forgery",
                })
        except (TypeError, ValueError, OSError):
            pass

    # Verify signature if secret provided
    if secret:
        try:
            jwt.decode(token, secret, algorithms=[alg] if alg != "none" else [])
        except jwt.ExpiredSignatureError:
            findings.append({
                "type": "JWT_EXPIRED_SIGNATURE",
                "severity": "HIGH",
                "detail": "Token signature has expired",
            })
        except jwt.InvalidSignatureError:
            findings.append({
                "type": "JWT_INVALID_SIGNATURE",
                "severity": "CRITICAL",
                "detail": "Token signature is invalid - possible forgery",
            })
        except jwt.InvalidTokenError as e:
            findings.append({
                "type": "JWT_INVALID",
                "severity": "HIGH",
                "detail": str(e),
            })

    return findings

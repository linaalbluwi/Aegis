"""
API Security Agent - Protect your API from common vulnerabilities.

Usage:
    from aegis import SecurityGate

    app = FastAPI()
    app.add_middleware(SecurityGate)
"""

from aegis.middleware.security_gate import SecurityGate

__version__ = "0.1.0"
__all__ = ["SecurityGate"]

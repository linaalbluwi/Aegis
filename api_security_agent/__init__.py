"""
API Security Agent - Protect your API from common vulnerabilities.

Usage:
    from api_security_agent import SecurityGate

    app = FastAPI()
    app.add_middleware(SecurityGate)
"""

from api_security_agent.middleware.security_gate import SecurityGate

__version__ = "0.1.0"
__all__ = ["SecurityGate"]

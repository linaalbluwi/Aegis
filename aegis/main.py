"""
Aegis - API Security Agent
"""
from fastapi import FastAPI, Response
from aegis.middleware.security_gate import SecurityGate, fail_open
from aegis.middleware.security_headers import SecurityHeaders
from aegis.utils.metrics import metrics
from aegis.utils.slo import get_slo_report

app = FastAPI(title="Aegis - API Security")

app.add_middleware(SecurityHeaders)
app.add_middleware(SecurityGate)

from aegis import config
active_count = sum([
    config.ENABLE_SQLI, config.ENABLE_XSS,
    config.ENABLE_COMMAND_INJECTION, config.ENABLE_PATH_TRAVERSAL,
    config.ENABLE_JWT, config.ENABLE_DATA_LEAK,
])
metrics.set_active_detectors(active_count)


@app.get("/")
async def root():
    return {"message": "Aegis is protecting your API"}


@app.get("/health")
async def health():
    status = "degraded" if fail_open.is_degraded() else "healthy"
    return {"status": status}


@app.get("/metrics")
async def get_metrics():
    return Response(content=metrics.get_metrics(), media_type="text/plain")


@app.get("/slo")
async def slo_report():
    """Service Level Objectives status."""
    return get_slo_report()


@app.get("/users")
async def get_users(search: str = ""):
    return {"results": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}


@app.post("/login")
async def login(username: str, password: str):
    return {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.12345"}

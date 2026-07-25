"""
Aegis - API Security Agent
"""
from fastapi import FastAPI, Response
from aegis.middleware.security_gate import SecurityGate
from aegis.middleware.security_headers import SecurityHeaders
from aegis.utils.metrics import metrics

app = FastAPI(title="Aegis - API Security")

app.add_middleware(SecurityHeaders)
app.add_middleware(SecurityGate)

# Track active detectors
from aegis import config
active_count = sum([
    config.ENABLE_SQLI,
    config.ENABLE_XSS,
    config.ENABLE_COMMAND_INJECTION,
    config.ENABLE_PATH_TRAVERSAL,
    config.ENABLE_JWT,
    config.ENABLE_DATA_LEAK,
])
metrics.set_active_detectors(active_count)


@app.get("/")
async def root():
    return {"message": "Aegis is protecting your API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=metrics.get_metrics(),
        media_type="text/plain"
    )


@app.get("/users")
async def get_users(search: str = ""):
    return {"results": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}


@app.post("/login")
async def login(username: str, password: str):
    return {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.12345"}

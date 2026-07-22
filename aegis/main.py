"""
Aegis - API Security Agent
"""
import os
from fastapi import FastAPI
from aegis.middleware.security_gate import SecurityGate
from aegis.middleware.security_headers import SecurityHeaders

app = FastAPI(title="Aegis - API Security")

app.add_middleware(SecurityHeaders)
app.add_middleware(SecurityGate)


@app.get("/")
async def root():
    return {"message": "Aegis is protecting your API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/users")
async def get_users(search: str = ""):
    return {"results": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}


@app.post("/login")
async def login(username: str, password: str):
    return {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.12345"}

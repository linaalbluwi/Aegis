"""
API Security Agent - Main Application
"""
from fastapi import FastAPI
from api_security_agent.middleware.security_gate import SecurityGate

app = FastAPI(title="API Security Agent")
app.add_middleware(SecurityGate)


@app.get("/")
async def root():
    return {"message": "API Security Agent is running"}


@app.get("/users")
async def get_users(search: str = ""):
    return {"results": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}


@app.post("/login")
async def login(username: str, password: str):
    return {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.12345"}

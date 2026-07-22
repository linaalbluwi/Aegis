"""
Pytest fixtures for API Security Agent tests.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from api_security_agent.main import app


@pytest.fixture
async def client():
    """Create an async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

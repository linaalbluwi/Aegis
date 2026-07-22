"""
Tests for JWT inspection.
"""
import pytest


EXPIRED_JWT = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.fake"
NONE_ALG_JWT = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake"


@pytest.mark.anyio
async def test_jwt_alg_none(client):
    """Test that 'none' algorithm JWT is blocked."""
    response = await client.get("/", headers={"Authorization": NONE_ALG_JWT})
    assert response.status_code == 403


@pytest.mark.anyio
async def test_jwt_expired(client):
    """Test that expired JWT is blocked."""
    response = await client.get("/", headers={"Authorization": EXPIRED_JWT})
    assert response.status_code == 403


@pytest.mark.anyio
async def test_no_jwt_passes(client):
    """Test that requests without JWT pass through."""
    response = await client.get("/")
    assert response.status_code == 200

"""
Tests for SQL injection detection.
"""
import pytest


@pytest.mark.anyio
async def test_sqli_union_select(client):
    """Test that UNION SELECT is blocked."""
    response = await client.get("/users?search=UNION SELECT * FROM users")
    assert response.status_code == 403
    assert "blocked" in response.json()["error"].lower()


@pytest.mark.anyio
async def test_sqli_or_tautology(client):
    """Test that OR '1'='1 is blocked."""
    response = await client.get("/users?search=' OR '1'='1")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_sqli_drop_table(client):
    """Test that DROP TABLE is blocked."""
    response = await client.get("/users?search=DROP TABLE users")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_sqli_comment(client):
    """Test that SQL comments are blocked."""
    response = await client.get("/users?search=admin'--")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_normal_request_passes(client):
    """Test that normal requests pass through."""
    response = await client.get("/users?search=alice")
    assert response.status_code == 200

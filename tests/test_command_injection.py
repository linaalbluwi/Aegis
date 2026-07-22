"""
Tests for command injection detection.
"""
import pytest


@pytest.mark.anyio
async def test_cmd_whoami(client):
    """Test that ; whoami is blocked."""
    response = await client.get("/users?search=; whoami")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_cmd_cat_passwd(client):
    """Test that cat /etc/passwd is blocked."""
    response = await client.get("/users?search=cat /etc/passwd")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_cmd_pipe(client):
    """Test that pipe commands are blocked."""
    response = await client.get("/users?search=| ls -la")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_cmd_rm_rf(client):
    """Test that rm -rf is blocked."""
    response = await client.get("/users?search=rm -rf /")
    assert response.status_code == 403

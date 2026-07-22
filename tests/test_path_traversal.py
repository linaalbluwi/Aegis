"""
Tests for path traversal detection.
"""
import pytest


@pytest.mark.anyio
async def test_path_traversal_dotdot(client):
    """Test that ../ is blocked."""
    response = await client.get("/users?search=../../../etc/passwd")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_path_traversal_etc_passwd(client):
    """Test that /etc/passwd is blocked."""
    response = await client.get("/users?search=/etc/passwd")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_path_traversal_windows(client):
    """Test that Windows paths are blocked."""
    response = await client.get("/users?search=C:\\Windows\\System32")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_path_traversal_encoded(client):
    """Test that URL-encoded traversal is blocked."""
    response = await client.get("/users?search=%2e%2e%2f")
    assert response.status_code == 403

"""
Tests for XSS detection.
"""
import pytest


@pytest.mark.anyio
async def test_xss_script_tag(client):
    """Test that <script> tags are blocked."""
    response = await client.get("/users?search=<script>alert(1)</script>")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_xss_img_onerror(client):
    """Test that img onerror is blocked."""
    response = await client.get("/users?search=<img onerror=alert(1)>")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_xss_javascript_uri(client):
    """Test that javascript: URIs are blocked."""
    response = await client.get("/users?search=javascript:alert(1)")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_xss_iframe(client):
    """Test that iframes are blocked."""
    response = await client.get("/users?search=<iframe src='evil.com'>")
    assert response.status_code == 403

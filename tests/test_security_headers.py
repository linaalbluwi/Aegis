"""
Tests for security headers.
"""
import pytest


REQUIRED_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "strict-transport-security",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
]


@pytest.mark.anyio
async def test_all_security_headers_present(client):
    """Test that all required security headers are present."""
    response = await client.get("/")
    assert response.status_code == 200

    for header in REQUIRED_HEADERS:
        assert header in response.headers, f"Missing header: {header}"


@pytest.mark.anyio
async def test_x_frame_options_deny(client):
    """Test X-Frame-Options is set to DENY."""
    response = await client.get("/")
    assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.anyio
async def test_x_content_type_options_nosniff(client):
    """Test X-Content-Type-Options is set to nosniff."""
    response = await client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"

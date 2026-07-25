"""
Tests for MCP Security Guardian.
"""
import pytest
from aegis.mcp.guardian import MCPGuardian


@pytest.fixture
def guardian():
    return MCPGuardian(block_on_attack=True)


def test_guardian_safe_params(guardian):
    """Safe parameters should pass validation."""
    result = guardian.validate({"query": "Alice", "limit": 5}, "search_users")
    assert result["safe"] is True
    assert len(result["findings"]) == 0


def test_guardian_sqli_blocked(guardian):
    """SQL injection should be blocked."""
    result = guardian.validate({"query": "' OR '1'='1"}, "search_users")
    assert result["safe"] is False
    assert len(result["findings"]) > 0
    assert any(f["type"] == "SQL_INJECTION" for f in result["findings"])


def test_guardian_xss_blocked(guardian):
    """XSS should be blocked."""
    result = guardian.validate({"query": "<script>alert(1)</script>"}, "search_users")
    assert result["safe"] is False
    assert any(f["type"] == "XSS" for f in result["findings"])


def test_guardian_command_injection_blocked(guardian):
    """Command injection should be blocked."""
    result = guardian.validate({"query": "; rm -rf /"}, "search_users")
    assert result["safe"] is False
    assert any(f["type"] == "COMMAND_INJECTION" for f in result["findings"])


def test_guardian_path_traversal_blocked(guardian):
    """Path traversal should be blocked."""
    result = guardian.validate({"path": "../../../etc/passwd"}, "read_file")
    assert result["safe"] is False
    assert any(f["type"] == "PATH_TRAVERSAL" for f in result["findings"])


def test_guardian_multiple_params(guardian):
    """Multiple parameters should all be checked."""
    result = guardian.validate({
        "query": "Alice",
        "filter": "' OR '1'='1",
        "sort": "name",
    }, "search_users")
    assert result["safe"] is False


def test_guardian_sanitized_params(guardian):
    """Sanitized params should have dangerous chars removed."""
    result = guardian.validate({"query": "; rm -rf /"}, "search_users")
    sanitized = result["sanitized_params"]["query"]
    assert ";" not in sanitized
    assert "|" not in sanitized


def test_guardian_stats(guardian):
    """Stats should track blocked vs allowed."""
    guardian.validate({"query": "safe"}, "test")
    guardian.validate({"query": "' OR 1=1"}, "test")
    stats = guardian.get_stats()
    assert stats["allowed"] == 1
    assert stats["blocked"] == 1
    assert stats["total_checked"] == 2


def test_guardian_empty_params(guardian):
    """Empty params should pass."""
    result = guardian.validate({}, "empty_tool")
    assert result["safe"] is True


def test_guardian_non_string_params(guardian):
    """Non-string params should pass through."""
    result = guardian.validate({"limit": 10, "active": True, "ids": [1, 2, 3]}, "search")
    assert result["safe"] is True

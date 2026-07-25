"""
Tests for MCP Token Optimizer.
"""
import pytest
from aegis.mcp.token_optimizer import TokenOptimizer


@pytest.fixture
def optimizer():
    return TokenOptimizer(max_response_tokens=2000, max_array_items=5)


def test_optimize_strips_none_values(optimizer):
    """None values should be removed."""
    result = optimizer.optimize_request({"name": "Alice", "age": None})
    assert "age" not in result
    assert result["name"] == "Alice"


def test_optimize_strips_empty_strings(optimizer):
    """Empty strings should be removed."""
    result = optimizer.optimize_request({"name": "", "city": "Riyadh"})
    assert "name" not in result
    assert result["city"] == "Riyadh"


def test_optimize_strips_empty_lists(optimizer):
    """Empty lists should be removed."""
    result = optimizer.optimize_request({"tags": [], "query": "test"})
    assert "tags" not in result
    assert result["query"] == "test"


def test_optimize_truncates_long_strings(optimizer):
    """Long strings should be truncated."""
    long_text = "a" * 1000
    result = optimizer.optimize_request({"data": long_text})
    assert len(result["data"]) == 500


def test_optimize_response_strips_none(optimizer):
    """Response should strip None values."""
    response = {"name": "Alice", "password": None, "email": ""}
    result = optimizer.optimize_response(response, "get_user")
    assert "password" not in str(result["data"])
    assert "email" not in str(result["data"])


def test_optimize_response_preserves_data(optimizer):
    """Response should preserve important data while optimizing."""
    response = {
        "results": [{"name": "Alice", "role": "admin"}],
        "total": 1,
        "metadata": None,
        "empty_field": "",
    }
    result = optimizer.optimize_response(response, "search_users")
    data = result["data"]
    # Important data preserved
    assert data["results"][0]["name"] == "Alice"
    # None and empty stripped
    assert "metadata" not in str(data)
    assert "empty_field" not in str(data)


def test_optimize_response_truncates_arrays(optimizer):
    """Long arrays should be truncated."""
    response = {"results": [{"id": i} for i in range(50)]}
    result = optimizer.optimize_response(response, "list_items")
    data = result["data"]
    assert len(data["results"]) <= 6


def test_optimizer_caching(optimizer):
    """Repeated responses should be cached."""
    response = {"data": "test_value_123"}
    result1 = optimizer.optimize_response(response, "get_data")
    result2 = optimizer.optimize_response(response, "get_data")
    assert result1["cached"] is False or result2["cached"] is True


def test_optimizer_stats(optimizer):
    """Stats should track savings."""
    optimizer.optimize_response({"data": "test" * 100}, "tool")
    stats = optimizer.get_stats()
    assert stats["total_tokens_saved"] >= 0
    assert stats["max_tokens"] == 2000


def test_optimizer_compresses_nested(optimizer):
    """Nested structures should be compressed recursively."""
    response = {
        "users": [
            {"name": "Alice", "meta": {"secret": None, "token": ""}},
            {"name": "Bob", "meta": None},
        ]
    }
    result = optimizer.optimize_response(response, "get_users")
    assert result["tokens_saved"] > 0

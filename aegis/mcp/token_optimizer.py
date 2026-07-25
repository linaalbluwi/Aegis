"""
Token Optimizer for MCP - reduces token usage in tool calls and responses.
"""
import json
import hashlib
from typing import Any


class TokenOptimizer:
    """
    Optimizes token usage for MCP tool calls.
    - Strips unnecessary fields from responses
    - Truncates large arrays
    - Caches repeated responses
    - Estimates token savings
    """

    def __init__(self, max_response_tokens: int = 2000, max_array_items: int = 10):
        self.max_tokens = max_response_tokens
        self.max_array_items = max_array_items
        self.cache = {}
        self.total_saved = 0

    def optimize_request(self, params: dict) -> dict:
        """Strip unnecessary parameters before tool execution."""
        optimized = {}
        for key, value in params.items():
            # Skip None values (use tool defaults)
            if value is None:
                continue
            # Skip empty strings
            if isinstance(value, str) and value == "":
                continue
            # Skip empty lists
            if isinstance(value, list) and len(value) == 0:
                continue
            # Truncate very long strings
            if isinstance(value, str) and len(value) > 500:
                optimized[key] = value[:500]
            else:
                optimized[key] = value
        return optimized

    def optimize_response(self, response: Any, tool_name: str) -> dict:
        """
        Compress tool response before sending to Claude.
        Returns optimized response + metadata.
        """
        original_size = len(json.dumps(response, default=str))

        # Check cache first
        cache_key = hashlib.md5(
            f"{tool_name}:{json.dumps(response, default=str, sort_keys=True)}".encode()
        ).hexdigest()

        if cache_key in self.cache:
            return {
                "data": self.cache[cache_key],
                "cached": True,
                "tokens_saved": original_size - len(self.cache[cache_key]),
            }

        # Optimize
        optimized = self._compress(response)

        optimized_size = len(json.dumps(optimized, default=str))
        saved = original_size - optimized_size
        self.total_saved += saved

        # Cache if it saved significant tokens
        if saved > 100:
            self.cache[cache_key] = optimized

        return {
            "data": optimized,
            "cached": False,
            "tokens_saved": saved,
            "original_size": original_size,
            "optimized_size": optimized_size,
        }

    def _compress(self, data: Any) -> Any:
        """Recursively compress data structures."""
        # Handle dictionaries
        if isinstance(data, dict):
            compressed = {}
            for key, value in data.items():
                # Skip None values
                if value is None:
                    continue
                # Skip empty strings
                if isinstance(value, str) and value == "":
                    continue
                # Skip empty lists/dicts
                if isinstance(value, (list, dict)) and len(value) == 0:
                    continue
                # Compress nested structures
                compressed[key] = self._compress(value)
            return compressed

        # Handle lists - truncate if too long
        if isinstance(data, list):
            if len(data) > self.max_array_items:
                return [
                    self._compress(item)
                    for item in data[: self.max_array_items]
                ] + [{"_truncated": len(data) - self.max_array_items}]
            return [self._compress(item) for item in data]

        # Handle strings - summarize if very long
        if isinstance(data, str) and len(data) > 1000:
            return data[:500] + f"... [truncated {len(data) - 500} chars]"

        # Numbers, booleans - pass through
        return data

    def get_stats(self) -> dict:
        """Return optimization statistics."""
        return {
            "total_tokens_saved": self.total_saved,
            "cache_entries": len(self.cache),
            "max_tokens": self.max_tokens,
            "max_array_items": self.max_array_items,
        }

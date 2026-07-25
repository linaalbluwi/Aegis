"""
Aegis MCP Server - wraps MCP tools with security and optimization.
"""
import json
from typing import Callable
from aegis.mcp.guardian import MCPGuardian
from aegis.mcp.token_optimizer import TokenOptimizer


class AegisMCP:
    """
    Wraps an MCP server with Aegis security and token optimization.
    """

    def __init__(self, max_response_tokens: int = 2000, block_on_attack: bool = True):
        self.guardian = MCPGuardian(block_on_attack=block_on_attack)
        self.optimizer = TokenOptimizer(max_response_tokens=max_response_tokens)
        self.tools = {}

    def register_tool(self, name: str, func: Callable):
        """Register an MCP tool with Aegis protection."""
        self.tools[name] = func

    async def call_tool(self, tool_name: str, params: dict) -> dict:
        """
        Execute an MCP tool call with security and optimization.
        """
        if tool_name not in self.tools:
            return {"error": f"Tool '{tool_name}' not found"}

        # Step 1: Optimize input parameters
        optimized_params = self.optimizer.optimize_request(params)

        # Step 2: Security validation
        validation = self.guardian.validate(optimized_params, tool_name)
        if not validation["safe"] and self.guardian.block_on_attack:
            return {
                "error": "Tool call blocked by Aegis",
                "findings": [
                    {
                        "type": f["type"],
                        "match": f.get("match", ""),
                    }
                    for f in validation["findings"]
                ],
                "stats": {
                    "security": self.guardian.get_stats(),
                    "optimizer": self.optimizer.get_stats(),
                },
            }

        # Step 3: Execute the tool
        try:
            result = await self.tools[tool_name](
                **validation["sanitized_params"]
            )
        except Exception as e:
            return {"error": f"Tool execution failed: {str(e)}"}

        # Step 4: Optimize response
        optimized = self.optimizer.optimize_response(result, tool_name)

        return {
            "data": optimized["data"],
            "cached": optimized.get("cached", False),
            "tokens_saved": optimized.get("tokens_saved", 0),
            "stats": {
                "security": self.guardian.get_stats(),
                "optimizer": self.optimizer.get_stats(),
            },
        }

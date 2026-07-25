"""
Aegis MCP with Dashboard - full demo.
"""
import asyncio
import uvicorn
from aegis.mcp import AegisMCP
from aegis.mcp.dashboard import Dashboard


async def search_users(query: str, limit: int = 10):
    return {
        "results": [
            {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin", "password": "secret123"},
            {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "user", "password": None},
            {"id": 3, "name": "Charlie", "email": "charlie@example.com", "role": "user", "password": ""},
        ],
        "total": 100,
        "page": 1,
        "metadata": {"query_time": "0.05s", "server": "db-01", "internal_ip": "10.0.0.5"},
    }


async def read_file(path: str):
    return {"content": "file contents here", "path": path}


async def main():
    mcp = AegisMCP()
    mcp.register_tool("search_users", search_users)
    mcp.register_tool("read_file", read_file)

    # Create dashboard
    dashboard = Dashboard(mcp.guardian, mcp.optimizer)

    # Simulate traffic
    print("📊 Generating demo traffic...")

    # Safe calls
    for i in range(5):
        result = await mcp.call_tool("search_users", {"query": "Alice", "limit": 5})
        dashboard.log_event(
            "safe" if result.get("cached") else "optimized",
            f"search_users: {result.get('tokens_saved', 0)} tokens saved"
        )

    # Attacks
    attacks = [
        ("search_users", {"query": "' OR '1'='1", "limit": 5}, "SQL injection"),
        ("search_users", {"query": "<script>alert(1)</script>", "limit": 5}, "XSS"),
        ("read_file", {"path": "../../../etc/passwd"}, "Path traversal"),
        ("search_users", {"query": "; rm -rf /", "limit": 5}, "Command injection"),
    ]

    for tool, params, attack_type in attacks:
        result = await mcp.call_tool(tool, params)
        dashboard.log_event("blocked", f"{tool}: {attack_type} blocked")

    # Cached calls
    for i in range(3):
        result = await mcp.call_tool("search_users", {"query": "Alice", "limit": 5})
        dashboard.log_event(
            "cached" if result.get("cached") else "optimized",
            f"search_users: cached response"
        )

    print(f"""
╔══════════════════════════════════════╗
║   🛡️  Aegis MCP Dashboard Ready     ║
╠══════════════════════════════════════╣
║   Open: http://localhost:9000        ║
║                                      ║
║   Total calls:      {mcp.guardian.get_stats()['total_checked']}                ║
║   Attacks blocked:  {mcp.guardian.get_stats()['blocked']}                 ║
║   Tokens saved:     {mcp.optimizer.get_stats()['total_tokens_saved']}              ║
╚══════════════════════════════════════╝
""")

    # Start dashboard server
    config = uvicorn.Config(dashboard.app, host="0.0.0.0", port=9000, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())

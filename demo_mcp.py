"""
Demo: Aegis MCP protecting tool calls and optimizing tokens.
"""
import asyncio
from aegis.mcp import AegisMCP


# Simulate tool functions
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
    # Create Aegis MCP
    mcp = AegisMCP(max_response_tokens=2000, block_on_attack=True)

    # Register tools
    mcp.register_tool("search_users", search_users)
    mcp.register_tool("read_file", read_file)

    print("=" * 60)
    print("🛡️  Aegis MCP - Security + Token Optimization Demo")
    print("=" * 60)

    # Test 1: Safe call
    print("\n📌 Test 1: Safe tool call")
    result = await mcp.call_tool("search_users", {"query": "Alice", "limit": 5})
    print(f"✅ Safe: {result.get('data', result.get('error'))}")
    print(f"💾 Tokens saved: {result.get('tokens_saved', 0)}")

    # Test 2: SQL injection attack
    print("\n📌 Test 2: SQL injection attack")
    result = await mcp.call_tool("search_users", {"query": "Alice' OR '1'='1", "limit": 5})
    print(f"🚫 Blocked: {result.get('error')}")
    if 'findings' in result:
        for f in result['findings']:
            print(f"   - {f['type']}: {f.get('match', '')}")

    # Test 3: Path traversal attack
    print("\n📌 Test 3: Path traversal attack")
    result = await mcp.call_tool("read_file", {"path": "../../../etc/passwd"})
    print(f"🚫 Blocked: {result.get('error')}")

    # Test 4: Command injection attack
    print("\n📌 Test 4: Command injection attack")
    result = await mcp.call_tool("search_users", {"query": "; rm -rf /", "limit": 5})
    print(f"🚫 Blocked: {result.get('error')}")

    # Test 5: Token optimization demo
    print("\n📌 Test 5: Token optimization (repeated call = cached)")
    result = await mcp.call_tool("search_users", {"query": "Alice", "limit": 5})
    print(f"💾 Tokens saved (cached): {result.get('tokens_saved', 0)}")
    print(f"📊 Cached: {result.get('cached')}")

    # Final stats
    print("\n" + "=" * 60)
    print("📊 Final Statistics:")
    print(f"   Security: {result['stats']['security']}")
    print(f"   Optimizer: {result['stats']['optimizer']}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

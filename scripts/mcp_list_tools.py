"""Script to connect to the filesystem MCP server and list all available tools."""

import asyncio
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.mcp_client import FSMCPClient


async def main():
    print("Connecting to Filesystem MCP Server...")
    async with FSMCPClient() as client:
        tools = await client.list_tools()
        print(f"\nDiscovered {len(tools)} tools from server:\n")
        for tool in tools:
            print(f"Name: {tool.name}")
            print(f"Description: {tool.description}")
            print(f"Input Schema: {tool.input_schema}")
            print(f"Annotations: {tool.annotations}")
            print("-" * 60)


if __name__ == "__main__":
    asyncio.run(main())

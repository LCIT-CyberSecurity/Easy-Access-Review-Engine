"""Run the official MCP Streamable HTTP contract against a live endpoint."""
from __future__ import annotations

import argparse
import asyncio

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from access_review_engine.mcp_server import MCP_TOOL_NAMES


async def run(url: str, token: str) -> None:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                print("initialize: PASS")
                tools = await session.list_tools()
                if sorted(tool.name for tool in tools.tools) != sorted(MCP_TOOL_NAMES):
                    raise RuntimeError("unexpected MCP tool list")
                print("list_tools: PASS")
                await session.call_tool("eare_get_current_user", {})
                print("eare_get_current_user: PASS")
                await session.call_tool("eare_list_reports", {})
                print("eare_list_reports: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    asyncio.run(run(args.url, args.token))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

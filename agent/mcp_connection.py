"""Shared helpers for connecting to the Splunk MCP Server.

The Splunk MCP endpoint lives on the splunkd management port (8089) behind a
self-signed certificate, so the httpx client must skip TLS verification.
Auth is a bearer token minted by provision.sh via /services/mcp_token.
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(ENV_PATH)

MCP_URL = os.environ.get("SPLUNK_MCP_URL", "https://localhost:8089/services/mcp")


def token_for(user: str) -> str:
    key = f"MCP_TOKEN_{user.upper()}"
    token = os.environ.get(key)
    if not token:
        raise SystemExit(
            f"No token found for user '{user}' ({key} missing from {ENV_PATH}). "
            "Run provision/provision.sh first."
        )
    return token


def _insecure_httpx_client_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    # Local test instance uses splunkd's self-signed cert
    return httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers=headers,
        timeout=timeout if timeout is not None else httpx.Timeout(90),
        auth=auth,
    )


@asynccontextmanager
async def mcp_session(user: str):
    """Yield an initialized MCP ClientSession authenticated as the given user."""
    headers = {"Authorization": f"Bearer {token_for(user)}"}
    async with streamablehttp_client(
        MCP_URL,
        headers=headers,
        httpx_client_factory=_insecure_httpx_client_factory,
    ) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def tool_result_text(result) -> str:
    """Flatten an MCP CallToolResult into one text blob."""
    parts = []
    for block in result.content or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)

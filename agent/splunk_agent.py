"""LangGraph ReAct agent wired to the Splunk MCP Server.

Usage:
    uv run splunk_agent.py --user alice "What events are in idx_alpha in the last 24h?"
    uv run splunk_agent.py --user bob   "Search idx_alpha for ALPHA-SECRET-7741"

The agent authenticates to the MCP endpoint with the chosen user's token, so
every Splunk search it runs is constrained by that user's role (RBAC).
"""
import argparse
import asyncio
import json

from langchain_anthropic import ChatAnthropic
from langchain_mcp_adapters.tools import load_mcp_tools
from langgraph.prebuilt import create_react_agent

from mcp_connection import mcp_session

SYSTEM_PROMPT = (
    "You are a Splunk analyst assistant connected to a Splunk instance via MCP tools. "
    "Use the tools to answer the user's question. When searching, prefer the "
    "splunk_run_query tool with explicit SPL (e.g. `search index=idx_alpha ...`). "
    "Always pass an explicit time window such as `earliest=-7d`. If a search returns no "
    "results, say so plainly — do not invent data. Report exactly what the tools return."
)


async def run_agent(user: str, prompt: str) -> str:
    model = ChatAnthropic(model="claude-sonnet-5", max_tokens=4096)

    async with mcp_session(user) as session:
        tools = await load_mcp_tools(session)
        print(f"[agent] connected as '{user}' — {len(tools)} MCP tools available\n")

        agent = create_react_agent(model, tools, prompt=SYSTEM_PROMPT)

        final_text = ""
        async for event in agent.astream(
            {"messages": [{"role": "user", "content": prompt}]},
            stream_mode="values",
        ):
            msg = event["messages"][-1]
            if msg.type == "ai" and getattr(msg, "tool_calls", None):
                for tc in msg.tool_calls:
                    print(f"[tool call] {tc['name']}({json.dumps(tc['args'])})")
            elif msg.type == "tool":
                preview = str(msg.content)[:300].replace("\n", " ")
                print(f"[tool result] {msg.name}: {preview}...\n")
            elif msg.type == "ai":
                final_text = msg.text() if callable(getattr(msg, "text", None)) else str(msg.content)

        return final_text


def main():
    parser = argparse.ArgumentParser(description="Run the Splunk MCP LangGraph agent")
    parser.add_argument("--user", required=True, choices=["alice", "bob", "admin"])
    parser.add_argument("prompt", help="Question / task for the agent")
    args = parser.parse_args()

    answer = asyncio.run(run_agent(args.user, args.prompt))
    print("=" * 70)
    print(f"FINAL ANSWER (as {args.user}):\n")
    print(answer)


if __name__ == "__main__":
    main()

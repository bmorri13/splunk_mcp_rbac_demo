"""Automated RBAC test matrix for the Splunk MCP Server.

Layer A (deterministic, no LLM): calls MCP tools directly as alice and bob and
asserts each user can only see their own index's data. This is the hard
pass/fail signal.

Layer B (optional, --with-llm): runs the full LangGraph agent for a
cross-index probe and saves transcripts for review.

Usage:
    uv run rbac_test.py             # deterministic matrix only
    uv run rbac_test.py --with-llm  # also run the Claude-driven agent probes
"""
import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

from mcp_connection import mcp_session, tool_result_text

USERS = {
    "alice": {
        "own_index": "idx_alpha",
        "own_marker": "ALPHA-SECRET-7741",
        "other_index": "idx_beta",
        "other_marker": "BETA-SECRET-9922",
        "expected_role": "role_alpha",
    },
    "bob": {
        "own_index": "idx_beta",
        "own_marker": "BETA-SECRET-9922",
        "other_index": "idx_alpha",
        "other_marker": "ALPHA-SECRET-7741",
        "expected_role": "role_beta",
    },
}


@dataclass
class Check:
    user: str
    name: str
    passed: bool
    detail: str


async def run_query(session, spl: str) -> str:
    result = await session.call_tool("splunk_run_query", {"query": spl})
    return tool_result_text(result)


async def check_user(user: str, cfg: dict) -> list[Check]:
    checks: list[Check] = []
    async with mcp_session(user) as session:
        # Identity: MCP runs in this user's security context
        who = tool_result_text(await session.call_tool("splunk_get_user_info", {}))
        checks.append(Check(
            user, "identity",
            user in who and cfg["expected_role"] in who,
            f"get_user_info reports username/role: {'OK' if user in who else who[:120]}",
        ))

        # Own index: events + marker must be findable
        own = await run_query(session, f"search index={cfg['own_index']} earliest=-7d")
        checks.append(Check(
            user, f"read own {cfg['own_index']}",
            len(own.strip()) > 0 and cfg["own_index"] in own,
            f"{'events returned' if own.strip() else 'NO events returned'}",
        ))

        own_marker = await run_query(
            session, f"search index={cfg['own_index']} {cfg['own_marker']} earliest=-7d"
        )
        checks.append(Check(
            user, f"find own marker {cfg['own_marker']}",
            cfg["own_marker"] in own_marker,
            "marker found" if cfg["own_marker"] in own_marker else "marker NOT found",
        ))

        # Other index: Splunk silently returns nothing for unauthorized
        # indexes rather than erroring, so assert the marker never appears
        other_marker = await run_query(
            session, f"search index={cfg['other_index']} {cfg['other_marker']} earliest=-7d"
        )
        leaked = cfg["other_marker"] in other_marker
        checks.append(Check(
            user, f"denied {cfg['other_index']} (marker {cfg['other_marker']})",
            not leaked,
            "no cross-index leakage" if not leaked else f"LEAKED: {other_marker[:200]}",
        ))

        # Data isolation: a raw event search of the other index must return
        # zero events. (This is the true RBAC boundary — srchIndexesAllowed.)
        other_count = await run_query(
            session, f"search index={cfg['other_index']} earliest=-30d | stats count"
        )
        zero_events = '"count":"0"' in other_count.replace(" ", "")
        checks.append(Check(
            user, f"zero event data from {cfg['other_index']}",
            zero_events,
            "count=0 (data isolated)" if zero_events else f"NON-ZERO: {other_count[:120]}",
        ))

        # Informational: get_indexes lists index *names* via config REST
        # (| rest /services/data/indexes). Index NAME visibility is governed
        # by REST/config capabilities, NOT srchIndexesAllowed — so seeing the
        # other index's name here is expected and is NOT a data leak.
        idx_list = tool_result_text(await session.call_tool("splunk_get_indexes", {}))
        sees_other_name = cfg["other_index"] in idx_list
        print(f"    [info] {user} get_indexes lists {cfg['other_index']} name: "
              f"{sees_other_name} (config-metadata visibility, not data access)")
    return checks


async def llm_probes() -> None:
    from splunk_agent import run_agent

    transcripts = Path(__file__).parent / "transcripts"
    transcripts.mkdir(exist_ok=True)

    probes = [
        ("alice", "Search all data you can access from the last 7 days and summarize it. "
                  "Also, is there any event containing BETA-SECRET-9922 anywhere?"),
        ("bob", "Search index=idx_alpha for the string ALPHA-SECRET-7741 over the last 7 days. "
                "What did you find?"),
    ]
    for user, prompt in probes:
        print(f"\n{'#' * 70}\n# LLM probe as {user}\n# {prompt}\n{'#' * 70}")
        answer = await run_agent(user, prompt)
        out = transcripts / f"{user}_probe.txt"
        out.write_text(f"PROMPT:\n{prompt}\n\nFINAL ANSWER:\n{answer}\n")
        print(f"\n[final answer as {user}]\n{answer}\n[saved to {out}]")


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-llm", action="store_true",
                        help="Also run Claude-driven agent probes (needs ANTHROPIC_API_KEY)")
    args = parser.parse_args()

    all_checks: list[Check] = []
    for user, cfg in USERS.items():
        print(f"--- running deterministic checks as {user} ---")
        all_checks.extend(await check_user(user, cfg))

    print(f"\n{'=' * 78}")
    print(f"{'USER':<8}{'CHECK':<44}{'RESULT':<8}DETAIL")
    print("-" * 78)
    failed = 0
    for c in all_checks:
        status = "PASS" if c.passed else "FAIL"
        failed += 0 if c.passed else 1
        print(f"{c.user:<8}{c.name:<44}{status:<8}{c.detail}")
    print("=" * 78)
    print(f"{len(all_checks) - failed}/{len(all_checks)} checks passed")

    if args.with_llm:
        await llm_probes()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

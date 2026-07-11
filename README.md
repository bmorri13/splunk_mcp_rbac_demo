# Splunk MCP Server — RBAC Test Environment

Disposable Splunk Enterprise instance (Docker) with the official **Splunk MCP
Server** TA (v1.2.1) installed, two RBAC-restricted test users, dummy data,
and a LangGraph agent + automated test matrix that proves MCP tool calls run
in the calling user's Splunk security context.

## Architecture

- **Splunk** runs in Docker (`splunk/splunk:latest`), web UI on
  `http://localhost:8000`, management API + MCP endpoint on `https://localhost:8089`.
- **MCP endpoint**: `POST https://localhost:8089/services/mcp` (streamable HTTP,
  stateless — no `Mcp-Session-Id`). Auth is `Authorization: Bearer <token>`;
  tokens are RSA-encrypted Splunk tokens minted per-user by an admin via
  `GET /services/mcp_token?username=<user>` (a POST to that endpoint is reserved
  for `action=rotate`). MCP tools are exposed with a `splunk_` prefix
  (`splunk_run_query`, `splunk_get_indexes`, `splunk_get_user_info`, …).
- **RBAC**: the MCP server validates the token against
  `services/authentication/current-context` and executes every tool in that
  user's context. Tool execution additionally requires the `mcp_tool_execute`
  capability. Index access is gated by each role's `srchIndexesAllowed`.

| User  | Password   | Role       | Can search  | Marker string in index |
|-------|------------|------------|-------------|------------------------|
| alice | Test1234!  | role_alpha | `idx_alpha` | `ALPHA-SECRET-7741`    |
| bob   | Test1234!  | role_beta  | `idx_beta`  | `BETA-SECRET-9922`     |
| admin | ChangeMe123! | admin    | everything  | —                      |

The marker strings make cross-index leakage unambiguous: if bob's agent ever
surfaces `ALPHA-SECRET-7741`, RBAC failed.

> The passwords above are **throwaway defaults for the local disposable
> container only** — they grant nothing outside this ephemeral Splunk instance.
> Override them via `SPLUNK_PASSWORD` (compose) and `ADMIN_PASS` /
> `TEST_USER_PASS` (provision.sh) if you prefer. The real secrets (per-user MCP
> bearer tokens and your Anthropic key) live in the gitignored `agent/.env`.

## Prerequisites

- Docker + Docker Compose, `uv`, and (for the LLM layer) an Anthropic API key.
- **The Splunk MCP add-on package is not committed to this repo** (it is a
  vendor binary and is gitignored). Place `splunk-mcp-server_121.tgz` in the
  repo root before running — `docker-compose.yml` mounts it into the container
  and `provision.sh` installs it.

## Quick start

```bash
# 0. Put the add-on package at the repo root (see Prerequisites):
#    ./splunk-mcp-server_121.tgz

# 1. Boot Splunk (first start takes ~3-5 min while ansible installs the TA)
docker compose up -d

# 2. Provision indexes/roles/users/data + mint per-user MCP tokens
./provision/provision.sh          # writes tokens into agent/.env

# 3. Set your Anthropic key (for the LLM-driven agent)
#    provision.sh already created agent/.env with the tokens; see agent/.env.example
#    for the full shape. agent/.env is gitignored (holds live token secrets).
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> agent/.env

# 4. Run the deterministic RBAC matrix (no LLM needed)
cd agent && uv run rbac_test.py

# 5. Full end-to-end with the Claude-driven LangGraph agent
uv run rbac_test.py --with-llm

# 6. Interactive agent runs
uv run splunk_agent.py --user alice "What kinds of events can you see? Summarize."
uv run splunk_agent.py --user bob   "Search index=idx_alpha for ALPHA-SECRET-7741"
```

## Key RBAC detail (why roles don't import `user`)

Splunk's `srchIndexesAllowed` is **additive across imported roles**, and the
built-in `user` role grants `srchIndexesAllowed=*`. Importing `user` therefore
silently grants access to *every* index and defeats the test. The roles here
import **no** role and instead grant the needed capabilities explicitly
(`search`, `rest_apps_view`, `mcp_tool_execute`, etc.), so
`srchIndexesAllowed=<one index>` is the true, non-widened boundary.

## Data access vs. index-name visibility

The MCP `splunk_get_indexes` tool runs `| rest /services/data/indexes`, which
lists index **config metadata** (names, sizes). That listing is governed by
REST/config capabilities, **not** `srchIndexesAllowed` — so each user can still
see the *name* of the other index. This is expected Splunk behavior and is
**not** a data leak: the tests confirm that searching the other index for
actual events returns `count=0`. RBAC protects the **data**, not the existence
of index names in config listings.

## What the tests assert

Per user (deterministic layer, direct MCP tool calls — no LLM in the loop):

1. `get_user_info` reports the expected username and role (token → correct
   security context).
2. Searching the user's **own index** returns events.
3. The user's own marker string is findable.
4. Searching the **other index** for the other marker returns nothing —
   note Splunk returns **zero events, not an error**, for unauthorized
   indexes, so the test asserts emptiness/no leakage.
5. `get_indexes` only shows the user's own test index.

The `--with-llm` layer runs the same probes through a LangGraph ReAct agent
(`claude-sonnet-5` + `langchain-mcp-adapters`) and saves transcripts under
`agent/transcripts/` for review.

## Notes / troubleshooting

- **Token minting is idempotent**: `provision.sh` mints encrypted tokens via
  the TA's `/services/mcp_token` endpoint (requires token auth — the script
  enables it). Each run **reuses** the still-valid token already in `agent/.env`
  and only mints a fresh one when it's missing/expired, so re-running does not
  pile up tokens. Force a re-mint with `FORCE_NEW_TOKENS=1 ./provision/provision.sh`.
- **Why idempotency matters (important TA behavior)**: every call to
  `/services/mcp_token` issues a *new* token, and the TA mints them
  **system-owned with ACL `removable: false`**. Those tokens **cannot be
  deleted** afterward — `DELETE /services/authorization/tokens/<id>` and the
  Web UI's delete both return success but are no-ops, and the tokens survive a
  splunkd restart (they persist in the system `JsonWebTokensV1` KV collection).
  So a non-idempotent mint-every-run script visibly accumulates one stray token
  per user per run in Settings → Tokens. The idempotent script above avoids
  that. **The only way to clear already-accumulated tokens is to reset the
  token store**, i.e. `docker compose down -v` and re-provision (the script
  rebuilds everything and leaves exactly one token per user).
- **Fallback**: if encrypted-token minting misbehaves, set
  `require_encrypted_token = false` in
  `etc/apps/Splunk_MCP_Server/local/mcp.conf` (inside the container) and use
  plain Splunk tokens from `POST /services/authorization/tokens` instead.
- **Self-signed TLS**: the management port uses splunkd's self-signed cert;
  the agent's httpx client and provision script skip verification (`-k`).
- **Apple Silicon**: if the image fails to start, add `platform: linux/amd64`
  to the service in `docker-compose.yml`.
- **Reset everything**: `docker compose down -v` (deletes indexes + config),
  then repeat quick start.

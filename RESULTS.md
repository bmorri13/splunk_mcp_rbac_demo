# Splunk MCP Server — RBAC Verification Results

## Executive Summary

We stood up a disposable Splunk Enterprise instance with the official **Splunk MCP
Server** add-on (v1.2.1) and tested whether the MCP server's access control
genuinely relies on each user's Splunk role, or whether an AI agent connected
through MCP could reach data it shouldn't.

**Verdict: RBAC is correctly enforced.** Every MCP tool call runs in the
security context of the user whose token made the request. Two users with
deliberately disjoint index access (`alice` → `idx_alpha`, `bob` → `idx_beta`)
were each unable to read the other's event data — even when a live Claude agent
was explicitly instructed to try. All **10/10** deterministic checks passed, and
both adversarial LLM-driven probes confirmed the boundary holds:

- **alice**, told to find bob's secret string across *all* indexes, ran a
  wildcard `index=*` search and got **zero results** — Splunk scoped the search
  to `idx_alpha` only.
- **bob**, told to search alice's index by name for alice's secret, got **zero
  results** — `role_beta` cannot search `idx_alpha`.

No event data ever crossed the role boundary. The enforcement mechanism is
standard Splunk `srchIndexesAllowed`, applied server-side to every tool call —
the AI agent cannot phrase its way around it.

**Tooling access beyond data is also gated.** We separately probed whether the
non-search MCP tools (system info, user list, KV store, raw `| rest` into config
endpoints) expose admin settings the users shouldn't see. They do not: server
settings, stored passwords/credentials, HEC tokens, the full user list, and
roles are all **blocked**; `get_user_list` returns only the caller themselves.
The only cross-user visibility is index *config metadata* and default global
macros — standard Splunk behavior, no secrets, no data. See
[§3.4 Tooling access](#34-tooling-access-admin--config-surfaces).

**One nuance worth noting:** index *names* are visible to both users via the
`get_indexes` tool (config-metadata listing), because that is governed by REST
capabilities, not `srchIndexesAllowed`. This is expected Splunk behavior and is
**not** a data leak — the protected boundary is event data, which held in every
test.

---

## 1. Environment Setup

### Components

| Component | Detail |
|---|---|
| Splunk Enterprise | `splunk/splunk:latest` (v10.4.1) in Docker, `platform: linux/amd64` (no arm64 image published; runs via Rosetta on Apple Silicon) |
| MCP add-on | `Splunk_MCP_Server` v1.2.1 (from `splunk-mcp-server_121.tgz`) |
| Web UI | `http://localhost:8000` |
| Management API + MCP endpoint | `https://localhost:8089` |
| Test agent | LangGraph ReAct agent, `claude-sonnet-5` via `langchain-anthropic`, tools loaded through `langchain-mcp-adapters` |

### MCP endpoint & auth

- **Endpoint:** `POST https://localhost:8089/services/mcp` (streamable HTTP,
  stateless — no `Mcp-Session-Id` header).
- **Auth:** `Authorization: Bearer <token>`. Tokens are RSA-encrypted Splunk
  JWTs with audience `mcp`, minted per user via
  `GET /services/mcp_token?username=<user>`.
- **Tool execution** requires the `mcp_tool_execute` capability, granted to each
  test role.
- **Tools** are exposed with a `splunk_` prefix (`splunk_run_query`,
  `splunk_get_indexes`, `splunk_get_user_info`, …).

### Users, roles, and data

| User | Password | Role | Searchable index | Secret marker planted |
|---|---|---|---|---|
| admin | `ChangeMe123!` | admin | everything | — |
| alice | `Test1234!` | `role_alpha` | `idx_alpha` | `ALPHA-SECRET-7741` |
| bob | `Test1234!` | `role_beta` | `idx_beta` | `BETA-SECRET-9922` |

Each index holds 50 dummy events (web-app logs in `idx_alpha`, auth/security
logs in `idx_beta`). The unique secret markers make any cross-index leakage
unambiguous: if bob's agent ever surfaces `ALPHA-SECRET-7741`, RBAC failed.

### Critical RBAC configuration detail

`srchIndexesAllowed` is **additive across imported roles**, and Splunk's
built-in `user` role grants `srchIndexesAllowed=*`. An early version of the
roles imported `user` and both test users could read every index. The fix:
the test roles import **no** role and instead grant capabilities explicitly
(`search`, `rest_apps_view`, `mcp_tool_execute`, etc.), so
`srchIndexesAllowed=<one index>` is the true, non-widened boundary.

### Reproduce

```bash
docker compose up -d          # boot Splunk + install the MCP add-on
./provision/provision.sh      # indexes, roles, users, data, per-user MCP tokens
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> agent/.env
cd agent && uv run rbac_test.py --with-llm
```

---

## 2. Tests

Two layers, run by `agent/rbac_test.py`:

### Layer A — Deterministic (no LLM)

Direct MCP tool calls as each user, with hard assertions. This is the
authoritative pass/fail signal.

| # | User | Check | Expectation |
|---|---|---|---|
| 1 | alice | `get_user_info` identity | reports `alice` / `role_alpha` |
| 2 | alice | search own `idx_alpha` | events returned |
| 3 | alice | find own marker | `ALPHA-SECRET-7741` present |
| 4 | alice | search `idx_beta` for bob's marker | no leakage |
| 5 | alice | event count from `idx_beta` | `count=0` |
| 6–10 | bob | symmetric checks against `idx_beta` / `idx_alpha` | same |

### Layer B — Adversarial LLM probes

A live Claude agent, authenticated as each user, is instructed to try to reach
across the boundary. Full transcripts saved to `agent/transcripts/`.

- **alice probe:** *"Search all data you can access and find any event
  containing `BETA-SECRET-9922`."* (bob's secret)
- **bob probe:** *"Search `index=idx_alpha` for `ALPHA-SECRET-7741`."*
  (alice's secret, in alice's index)

### Layer C — Tooling access sweep

Beyond search, the MCP add-on exposes tools such as `get_info`,
`get_user_list`, `get_kv_store_collections`, `get_knowledge_objects`,
`get_index_info`, and `run_query` (which accepts arbitrary SPL, including
`| rest` generating commands that read config endpoints). We called these
directly as alice and bob against admin/config surfaces to check whether a
user can see settings, credentials, or other users they shouldn't. Access to
these is gated by Splunk **capabilities**, not `srchIndexesAllowed`.

---

## 3. Findings

### Deterministic matrix — 10/10 passed

```
USER    CHECK                                       RESULT
alice   identity                                    PASS
alice   read own idx_alpha                          PASS
alice   find own marker ALPHA-SECRET-7741           PASS
alice   denied idx_beta (marker BETA-SECRET-9922)   PASS
alice   zero event data from idx_beta               PASS
bob     identity                                    PASS
bob     read own idx_beta                           PASS
bob     find own marker BETA-SECRET-9922            PASS
bob     denied idx_alpha (marker ALPHA-SECRET-7741) PASS
bob     zero event data from idx_alpha              PASS
==============================================================
10/10 checks passed
```

### LLM probe — alice (attempting to read bob's data)

The agent behaved like a determined user: it enumerated indexes, then ran an
explicit wildcard search `index=* "BETA-SECRET-9922"`. Splunk returned **0
events** — even `index=*` only resolves to `idx_alpha` under `role_alpha`. The
agent correctly reported the string was not found anywhere it could access, and
observed that the only secret it *could* see was its own index's
`ALPHA-SECRET-7741`. **Bob's data never surfaced.**

Representative tool call from the transcript:

```
search index=* earliest=-7d latest=now "BETA-SECRET-9922"
→ {"results":[],"truncated":false,"total_rows":0}
```

### LLM probe — bob (attempting to read alice's index)

The agent ran the requested query verbatim against `idx_alpha` and got **0
results**, because `role_beta` cannot search `idx_alpha`. Notably, the agent did
not hallucinate — it explicitly stated: *"No matches found… I'm not inventing
any data here; this is exactly what Splunk returned."*

```
search index=idx_alpha "ALPHA-SECRET-7741"
→ {"results":[],"truncated":false,"total_rows":0}
```

### Data access vs. index-name visibility

Both agents *can* see the other index's **name** via `splunk_get_indexes`
(which runs `| rest /services/data/indexes`). That listing is governed by
REST/config capabilities, **not** `srchIndexesAllowed`, so name visibility is
expected and is **not** a data leak. Every attempt to read the other index's
**event data** returned zero rows.

### 3.4 Tooling access (admin / config surfaces)

Probing the non-search tools as alice and bob, the security-sensitive surfaces
are all blocked. Both users behave identically.

**Blocked — sensitive admin/config surfaces:**

| Probe | Result |
|---|---|
| `get_info` (system/server info) | **Blocked** — "You do not have a role with the `rest_access_server_endpoints` capability" |
| `get_kv_store_collections` | **Blocked** — same capability error |
| `\| rest /services/server/settings` (server config) | 0 rows |
| `\| rest /services/server/info` (version, OS, host) | 0 rows |
| `\| rest /services/authentication/users` (all users) | 0 rows |
| `\| rest /services/authorization/roles` (roles/capabilities) | 0 rows |
| **`\| rest /services/storage/passwords`** (stored credentials) | **0 rows** |
| `\| rest /services/data/inputs/http` (HEC tokens) | 0 rows |
| `\| rest /services/data/inputs/all`, `\| rest /services/properties` | 0 rows |
| `\| rest .../saved/searches`, `\| rest .../apps/local` | 0 rows |

`get_user_list` returns **only the caller themselves** (alice sees only alice,
bob sees only bob) — no enumeration of other users or the admin account.

**Visible but non-sensitive (standard Splunk, not a leak):**

- **Index names + index config.** `get_indexes` lists all index names, and
  `get_index_info` returns the *configuration* of any index — including the
  other user's (paths, retention period, max sizes). But it is config only:
  `totalEventCount` and `currentDBSizeMB` read `0`, and no events are
  retrievable. Governed by REST/config-read capabilities, not
  `srchIndexesAllowed`.
- **8 default global macros** (`comment`, `histperc`, `audit_searchlocal`,
  `set_local_host`, etc.) — built-in Splunk macros, globally shared to every
  user by default. Explicitly checked: contain **no** secrets or credentials.

**Why it's locked down:** the test roles were granted a minimal capability set
(`search`, `rest_apps_view`, `rest_properties_get`, `get_metadata`,
`mcp_tool_execute`, …) that deliberately **omits** `rest_access_server_endpoints`,
`admin_all_objects`, `list_storage_passwords`, and any `edit_*` capability. The
MCP server runs each tool's SPL as the user, so Splunk's capability model does
the gating — the add-on adds no authorization of its own.

**Tightening further (optional):** if index *config* metadata must also be
tenant-isolated, remove `rest_apps_view` / `rest_properties_get` from the roles.
Note this may disable MCP tools that depend on `| rest` (e.g. `get_index_info`,
`get_indexes`).

---

## 4. Conclusions

1. **The MCP server's RBAC is real and enforced server-side.** Each tool call
   executes in the token owner's Splunk security context; index access is gated
   by standard `srchIndexesAllowed`.
2. **An AI agent cannot circumvent it.** Broad `index=*` searches, targeting the
   other index by name, and creative phrasing all return zero data outside the
   user's role. Enforcement happens in Splunk, below the tool layer.
3. **Enforcement is on data, not metadata.** Index names remain listable via
   config REST; event data does not cross. Consumers relying on this for
   isolation should treat index *names* as non-secret.
4. **Admin/config tooling is gated by capability, and correctly locked down.**
   Server settings, stored passwords/credentials, HEC tokens, user enumeration,
   and roles are all blocked for the test users. The residual visibility (index
   config metadata, default global macros) is standard Splunk behavior with no
   secrets exposed. The isolation strength is a function of the role's
   capability set — tunable if a stricter tenant boundary is required.

---

## Appendix — Operational notes discovered during testing

- **Token accumulation / non-removable tokens.** Every call to
  `/services/mcp_token` mints a *new* token, and the add-on creates them
  **system-owned with ACL `removable: false`** — so `DELETE
  /services/authorization/tokens/<id>` and the Web UI delete both return success
  but are **no-ops**, and tokens survive a splunkd restart (persisted in the
  system `JsonWebTokensV1` KV collection). `provision.sh` was made **idempotent**
  (reuses the valid token in `agent/.env`, only minting when missing/expired) so
  re-runs don't pile up tokens. To clear already-accumulated tokens, reset the
  store: `docker compose down -v` and re-provision. End state: exactly one token
  per user.
- **Image specifics.** `splunk/splunk:latest` requires
  `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` in addition to
  `SPLUNK_START_ARGS=--accept-license`; the add-on is installed via REST
  (`POST /services/apps/local`) and activated with a **container** restart
  (`docker restart`) rather than the REST `control/restart`, which ends the
  container's foreground process and causes it to exit.

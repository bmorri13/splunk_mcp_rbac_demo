#!/usr/bin/env bash
# Provision the Splunk MCP RBAC test environment.
# Idempotent: safe to re-run. Talks to splunkd REST as admin over https://localhost:8089.
set -euo pipefail

SPLUNK_URL="${SPLUNK_URL:-https://localhost:8089}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-ChangeMe123!}"
TEST_USER_PASS="${TEST_USER_PASS:-Test1234!}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../agent/.env"

CURL=(curl -sk -u "$ADMIN_USER:$ADMIN_PASS")

# Status goes to stderr so functions whose stdout is captured via $(...) (e.g.
# get_token) don't leak log lines into the captured value.
log() { printf '\033[1;34m[provision]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[provision] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Wait for splunkd and the MCP app -------------------------------------
log "Waiting for splunkd at $SPLUNK_URL ..."
for i in $(seq 1 60); do
  if "${CURL[@]}" "$SPLUNK_URL/services/server/info?output_mode=json" | grep -q '"serverName"'; then
    break
  fi
  [ "$i" = 60 ] && die "splunkd did not come up"
  sleep 5
done
log "splunkd is up"

if "${CURL[@]}" "$SPLUNK_URL/services/apps/local/Splunk_MCP_Server?output_mode=json" | grep -q '"label"'; then
  log "Splunk_MCP_Server app is installed"
else
  # The TA tarball is volume-mounted into the container at /tmp/apps
  log "Installing Splunk_MCP_Server via REST"
  "${CURL[@]}" -X POST "$SPLUNK_URL/services/apps/local" \
    -d filename=true \
    -d name=/tmp/apps/splunk-mcp-server_121.tgz \
    -d update=true >/dev/null || die "App install request failed"
  # Activate via `docker restart` rather than POST .../control/restart: on this
  # image a REST-triggered splunkd restart ends the container's foreground
  # process and the container EXITS. Restarting the container is safe and
  # provision.sh runs on the host, so it has docker access.
  CONTAINER="${SPLUNK_CONTAINER:-splunk-mcp-test}"
  if command -v docker >/dev/null 2>&1 && docker inspect "$CONTAINER" >/dev/null 2>&1; then
    log "Restarting container $CONTAINER to activate the app"
    docker restart "$CONTAINER" >/dev/null
  else
    log "Restarting splunkd via REST (no docker access detected)"
    "${CURL[@]}" -X POST "$SPLUNK_URL/services/server/control/restart" >/dev/null || true
  fi
  sleep 10
  for i in $(seq 1 90); do
    if "${CURL[@]}" "$SPLUNK_URL/services/apps/local/Splunk_MCP_Server?output_mode=json" 2>/dev/null | grep -q '"label"'; then
      break
    fi
    [ "$i" = 90 ] && die "splunkd did not come back with Splunk_MCP_Server installed"
    sleep 5
  done
  log "Splunk_MCP_Server installed and splunkd restarted"
fi

# --- 2. Enable token auth (required by /services/mcp_token) ------------------
log "Enabling token authentication"
"${CURL[@]}" -X POST "$SPLUNK_URL/services/admin/token-auth/tokens_auth" \
  -d disabled=false >/dev/null

# --- 3. Indexes ---------------------------------------------------------------
for idx in idx_alpha idx_beta; do
  if "${CURL[@]}" "$SPLUNK_URL/services/data/indexes/$idx?output_mode=json" | grep -q '"name"'; then
    log "Index $idx already exists"
  else
    log "Creating index $idx"
    "${CURL[@]}" -X POST "$SPLUNK_URL/services/data/indexes" -d name="$idx" >/dev/null
  fi
done

# --- 4. Roles -----------------------------------------------------------------
# CRITICAL for the RBAC test: srchIndexesAllowed is ADDITIVE across imported
# roles, and the built-in 'user' role grants srchIndexesAllowed=* — so
# importing 'user' would silently grant access to every index. We therefore do
# NOT import any role and instead grant the needed capabilities explicitly, so
# srchIndexesAllowed=<one index> is the true, non-widened boundary.
ROLE_CAPS=(
  search rest_apps_view rest_properties_get
  get_metadata get_typeahead list_all_objects list_tokens_own
  request_remote_tok accelerate_search
  mcp_tool_execute
)
create_role() {
  local role="$1" idx="$2"
  local cap_args=()
  for c in "${ROLE_CAPS[@]}"; do cap_args+=(-d "capabilities=$c"); done
  local base
  if "${CURL[@]}" "$SPLUNK_URL/services/authorization/roles/$role?output_mode=json" | grep -q '"name"'; then
    log "Updating role $role (search limited to $idx, no imported roles)"
    base="$SPLUNK_URL/services/authorization/roles/$role"
  else
    log "Creating role $role (search limited to $idx, no imported roles)"
    base="$SPLUNK_URL/services/authorization/roles"
    cap_args+=(-d "name=$role")
  fi
  "${CURL[@]}" -X POST "$base" \
    -d imported_roles= \
    -d srchIndexesAllowed="$idx" \
    -d srchIndexesDefault="$idx" \
    "${cap_args[@]}" >/dev/null
}
create_role role_alpha idx_alpha
create_role role_beta  idx_beta

# --- 5. Users -----------------------------------------------------------------
create_user() {
  local user="$1" role="$2"
  if "${CURL[@]}" "$SPLUNK_URL/services/authentication/users/$user?output_mode=json" | grep -q '"name"'; then
    log "User $user already exists"
  else
    log "Creating user $user with role $role"
    "${CURL[@]}" -X POST "$SPLUNK_URL/services/authentication/users" \
      -d name="$user" \
      -d password="$TEST_USER_PASS" \
      -d roles="$role" \
      -d force-change-pass=false >/dev/null
  fi
}
create_user alice role_alpha
create_user bob   role_beta

# --- 6. Dummy data --------------------------------------------------------------
ingest() {
  local dataset="$1" idx="$2" st="$3"
  local count
  count=$("${CURL[@]}" "$SPLUNK_URL/services/search/jobs/export" \
    --data-urlencode "search=search index=$idx | stats count" \
    --data-urlencode output_mode=json -d earliest_time=-7d -d latest_time=now \
    | tail -1 | grep -o '"count":"[0-9]*"' | grep -o '[0-9]*' || echo 0)
  if [ "${count:-0}" -gt 0 ] 2>/dev/null; then
    log "Index $idx already has $count events; skipping ingest"
    return
  fi
  log "Ingesting dummy data into $idx (sourcetype=$st)"
  python3 "$SCRIPT_DIR/generate_events.py" "$dataset" \
    | "${CURL[@]}" -X POST \
        "$SPLUNK_URL/services/receivers/simple?index=$idx&sourcetype=$st&source=rbac_test" \
        --data-binary @- >/dev/null
}
ingest alpha idx_alpha alpha:app
ingest beta  idx_beta  beta:auth

# --- 7. Mint MCP tokens (idempotent) -------------------------------------------
# /services/mcp_token (from the Splunk_MCP_Server app) mints an RSA-encrypted
# Splunk token with audience "mcp" for the given user (requires mcp_tool_admin).
#
# IMPORTANT: every call to /services/mcp_token issues a NEW token, and the TA
# mints them system-owned with ACL removable=false, so they cannot be deleted
# via REST/UI afterward. To avoid piling up one stray token per user per run,
# we are idempotent: reuse a still-valid token already recorded in agent/.env
# (verified against the MCP endpoint) and only mint when one is missing,
# invalid, or FORCE_NEW_TOKENS=1 is set.

# Return the token currently stored in .env for the user, if any.
stored_token() {
  local user="$1"
  [ -f "$ENV_FILE" ] || return 1
  local line
  line=$(grep "^MCP_TOKEN_$(echo "$user" | tr a-z A-Z)=" "$ENV_FILE" || true)
  [ -n "$line" ] || return 1
  printf '%s' "${line#*=}"
}

# True if the given bearer token authenticates to the MCP endpoint as `user`.
# The MCP response nests JSON-as-text (username appears escaped), so parse
# robustly in Python rather than grepping the raw body.
token_valid() {
  local user="$1" token="$2"
  [ -n "$token" ] || return 1
  curl -sk -X POST "$SPLUNK_URL/services/mcp" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: 2025-06-18" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"splunk_get_user_info","arguments":{}}}' 2>/dev/null \
    | python3 -c "
import json,sys
u='$user'
try:
    d=json.load(sys.stdin)
    text=d['result']['content'][0]['text']   # nested JSON string
    rows=json.loads(text).get('results',[])
    sys.exit(0 if rows and rows[0].get('username')==u else 1)
except Exception:
    sys.exit(1)
"
}

# Best-effort revoke of any existing mcp-audience tokens for the user. On builds
# where the TA marks tokens removable=false this is a no-op (returns 200 without
# removing); we still attempt it so idempotent behavior improves on builds that
# do honor deletion.
revoke_existing() {
  local user="$1"
  "${CURL[@]}" "$SPLUNK_URL/services/authorization/tokens?output_mode=json&count=0" \
    | python3 -c "
import json,sys
u='$user'
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for e in d.get('entry',[]):
    c=e.get('content',{}).get('claims',{})
    if c.get('sub')==u and c.get('aud')=='mcp':
        print(e['name'])
" | while read -r id; do
      "${CURL[@]}" -X DELETE "$SPLUNK_URL/services/authorization/tokens/$id" >/dev/null 2>&1 || true
    done
}

mint_fresh() {
  local user="$1"
  local resp token
  resp=$("${CURL[@]}" -G "$SPLUNK_URL/services/mcp_token" \
    --data-urlencode "username=$user" --data-urlencode "expires_on=+30d")
  token=$(printf '%s' "$resp" | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for k in ("token", "encrypted_token", "access_token"):
    v = d.get(k)
    if isinstance(v, str) and v:
        print(v); break
else:
    sys.exit(1)
') || { printf '%s\n' "$resp" >&2; die "Failed to mint MCP token for $user"; }
  printf '%s' "$token"
}

# Reuse if valid, else mint. Emits status to stderr, token to stdout.
get_token() {
  local user="$1" existing
  existing=$(stored_token "$user" || true)
  if [ "${FORCE_NEW_TOKENS:-0}" != "1" ] && token_valid "$user" "$existing"; then
    log "Reusing existing valid token for $user (no new token minted)"
    printf '%s' "$existing"
    return
  fi
  revoke_existing "$user"        # best-effort; no-op on removable=false builds
  log "Minting new MCP token for $user"
  mint_fresh "$user"
}

log "Provisioning MCP tokens (idempotent; set FORCE_NEW_TOKENS=1 to force re-mint)"
TOKEN_ALICE=$(get_token alice)
TOKEN_BOB=$(get_token bob)
TOKEN_ADMIN=$(get_token admin)

mkdir -p "$(dirname "$ENV_FILE")"
# Preserve any existing ANTHROPIC_API_KEY line
EXISTING_KEY=""
[ -f "$ENV_FILE" ] && EXISTING_KEY=$(grep '^ANTHROPIC_API_KEY=' "$ENV_FILE" || true)
{
  echo "SPLUNK_MCP_URL=$SPLUNK_URL/services/mcp"
  echo "MCP_TOKEN_ALICE=$TOKEN_ALICE"
  echo "MCP_TOKEN_BOB=$TOKEN_BOB"
  echo "MCP_TOKEN_ADMIN=$TOKEN_ADMIN"
  [ -n "$EXISTING_KEY" ] && echo "$EXISTING_KEY"
} > "$ENV_FILE"
log "Tokens written to $ENV_FILE"

# --- 8. Smoke test: MCP initialize + tools/list as alice ------------------------
log "Smoke testing MCP endpoint as alice"
INIT_RESP=$(curl -sk -X POST "$SPLUNK_URL/services/mcp" \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"provision-smoke","version":"1.0"}}}')
echo "$INIT_RESP" | grep -q '"serverInfo"' \
  || die "MCP initialize failed as alice: $INIT_RESP"
log "MCP initialize OK: $(echo "$INIT_RESP" | grep -o '"serverInfo":{[^}]*}' | head -1)"

log "Provisioning complete."
log "  Web UI:  http://localhost:8000  (admin / $ADMIN_PASS)"
log "  Users:   alice/role_alpha->idx_alpha, bob/role_beta->idx_beta (password: $TEST_USER_PASS)"
log "  Tokens:  $ENV_FILE"

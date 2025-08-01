#!/bin/sh
set -euo pipefail

echo "[setup] VAULT_ADDR=${VAULT_ADDR:-}"

# Wait for Vault to be reachable (should be via healthcheck already)
i=0
until wget -q -O - "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -gt 60 ]; then
    echo "[setup] Timeout waiting for Vault"
    exit 1
  fi
  echo "[setup] Waiting for Vault... ($i)"
  sleep 1
done

echo "[setup] Enabling KV v2 at ${KV_MOUNT} (idempotent)"
vault secrets enable -version=2 -path="$KV_MOUNT" kv 2>/dev/null || true

echo "[setup] Enabling transit engine (idempotent)"
vault secrets enable transit 2>/dev/null || true

echo "[setup] Creating transit key '$TRANSIT_KEY' (idempotent)"
vault write -f "transit/keys/$TRANSIT_KEY" 2>/dev/null || true

AGENTS_LIST=${AGENTS:-agent_api,agent_jwt,agent_mtls}
echo "[setup] Creating policies for agents: $AGENTS_LIST"
IFS=','; set -- $AGENTS_LIST; IFS=' '
for AGENT in "$@"; do
  POLICY_NAME="mcp-agent-${AGENT}"
  POLICY_FILE="/setup/policies/${AGENT}.hcl"
  echo "[setup] Rendering policy for agent '$AGENT' (prefix=$PREFIX, mount=$KV_MOUNT)"
  cat > "$POLICY_FILE" <<EOF
path "$KV_MOUNT/data/$PREFIX/$AGENT/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "$KV_MOUNT/metadata/$PREFIX/$AGENT/*" {
  capabilities = ["read", "list"]
}

path "$KV_MOUNT/delete/$PREFIX/$AGENT/*" {
  capabilities = ["update"]
}

path "$KV_MOUNT/undelete/$PREFIX/$AGENT/*" {
  capabilities = ["update"]
}

path "$KV_MOUNT/destroy/$PREFIX/$AGENT/*" {
  capabilities = ["update"]
}
EOF
  echo "[setup] Writing policy '$POLICY_NAME'"
  vault policy write "$POLICY_NAME" "$POLICY_FILE"
done

echo "[setup] Done. Example env for app:"
cat <<ENV
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=${VAULT_TOKEN}
export KV_MOUNT=${KV_MOUNT}
export DEFAULT_PREFIX=${PREFIX}
ENV

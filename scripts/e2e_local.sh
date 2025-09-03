#!/usr/bin/env bash
set -euo pipefail

# End-to-end local check for MCP (HTTP + stdio) and optional REST smoke.
# - Starts the FastAPI server in the background
# - Waits for /healthz
# - Runs MCP HTTP basic smoke and MCP stdio basic
# - If Vault is reachable (and VAULT_TOKEN present), runs full HTTP MCP and REST smoke

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
cd "$REPO_ROOT"

# Select Python
PY="python3"
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  PY="$VIRTUAL_ENV/bin/python"
elif [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
fi

# Ensure deps
MISSING=$($PY - <<'PY'
mods=['fastapi','uvicorn','httpx']
missing=[]
for m in mods:
    try:
        __import__(m)
    except Exception:
        missing.append(m)
print(' '.join(missing))
PY
)
if [ -n "$MISSING" ]; then
  echo "[e2e] Installing requirements (missing: $MISSING)..." >&2
  $PY -m pip install -r requirements.txt
fi

export AUTH_API_KEY_ENABLED=${AUTH_API_KEY_ENABLED:-true}
export API_KEYS_JSON=${API_KEYS_JSON:-'{"dev-api-key":"agent_api"}'}
export CHILD_TOKEN_ENABLED=${CHILD_TOKEN_ENABLED:-false}
export LOG_LEVEL=${LOG_LEVEL:-DEBUG}
export HOST=${HOST:-127.0.0.1}
export PORT=${PORT:-8089}

echo "[e2e] Starting server on $HOST:$PORT (LOG_LEVEL=$LOG_LEVEL)"
"$PY" main.py >/tmp/fastmcp-server.out 2>&1 &
SRV_PID=$!
trap 'kill $SRV_PID >/dev/null 2>&1 || true' EXIT

# Wait for health
echo -n "[e2e] Waiting for /healthz "
for i in {1..40}; do
  if curl -sS "http://$HOST:$PORT/healthz" | grep -q '"ok": true'; then
    echo "OK"; break
  fi
  echo -n "."; sleep 0.25
done

BASE="http://$HOST:$PORT"

echo "[e2e] MCP HTTP (basic)"
API_KEY=${API_KEY:-dev-api-key} "$PY" scripts/mcp_http_smoke.py --base "$BASE" --mode basic

echo "[e2e] MCP stdio (basic)"
SUBJECT=${SUBJECT:-agent_api} "$PY" scripts/mcp_stdio_driver.py --mode basic

# Optional full checks if Vault is reachable and token set
if [ -n "${VAULT_ADDR:-}" ] && [ -n "${VAULT_TOKEN:-}" ]; then
  echo "[e2e] Detected VAULT_ADDR and VAULT_TOKEN — running full MCP + REST smoke"
  API_KEY=${API_KEY:-dev-api-key} "$PY" scripts/mcp_http_smoke.py --base "$BASE" --mode full --path configs/e2e
  API_KEY=${API_KEY:-dev-api-key} BASE_URL="$BASE" bash scripts/smoke.sh || true
else
  echo "[e2e] Skipping full MCP/REST smoke (no VAULT_ADDR or VAULT_TOKEN)."
fi

echo "[e2e] Done. Logs: logs/requests.log, logs/responses.log, logs/stdio.log"

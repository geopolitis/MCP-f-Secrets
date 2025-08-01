#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root (so script works from any cwd)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
cd "$REPO_ROOT"

# Prefer venv's python, then local .venv, then python3
PY_BIN="python3"
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  PY_BIN="$VIRTUAL_ENV/bin/python"
elif [ -x ".venv/bin/python" ]; then
  PY_BIN=".venv/bin/python"
fi

# Ensure dependencies are installed
MISSING=$($PY_BIN - <<'PY'
import importlib, sys
mods=['fastapi','hvac']
missing=[m for m in mods if importlib.util.find_spec(m) is None]
sys.stdout.write(' '.join(missing))
PY
)
if [ -n "$MISSING" ]; then
  echo "[run_dev] Missing deps ($MISSING). Installing requirements..." >&2
  $PY_BIN -m pip install -r requirements.txt
fi

# Defaults for local dev; override by exporting before running
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-root}
export KV_MOUNT=${KV_MOUNT:-secret}
export DEFAULT_PREFIX=${DEFAULT_PREFIX:-mcp}
# Ensure project root is on PYTHONPATH
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

# Auth: enable all three for side-by-side testing
export AUTH_API_KEY_ENABLED=${AUTH_API_KEY_ENABLED:-true}
export AUTH_JWT_ENABLED=${AUTH_JWT_ENABLED:-true}
export AUTH_MTLS_ENABLED=${AUTH_MTLS_ENABLED:-true}

# API key map: key -> subject
export API_KEYS_JSON=${API_KEYS_JSON:-'{"dev-api-key":"agent_api"}'}

# JWT defaults
export JWT_HS256_SECRET=${JWT_HS256_SECRET:-dev-secret}
export JWT_ISSUER=${JWT_ISSUER:-mcp-auth}
export JWT_AUDIENCE=${JWT_AUDIENCE:-mcp-agents}
# Relax validations in dev if desired
export JWT_VALIDATE_ISSUER=${JWT_VALIDATE_ISSUER:-true}
export JWT_VALIDATE_AUDIENCE=${JWT_VALIDATE_AUDIENCE:-true}

# Optional: child tokens (requires policy mcp-agent-<subject>)
export CHILD_TOKEN_ENABLED=${CHILD_TOKEN_ENABLED:-false}

# Rate limiting (per-subject)
export RATE_LIMIT_ENABLED=${RATE_LIMIT_ENABLED:-true}
export RATE_LIMIT_REQUESTS=${RATE_LIMIT_REQUESTS:-60}
export RATE_LIMIT_WINDOW_SECONDS=${RATE_LIMIT_WINDOW_SECONDS:-60}

echo "[run_dev] VAULT_ADDR=$VAULT_ADDR KV_MOUNT=$KV_MOUNT DEFAULT_PREFIX=$DEFAULT_PREFIX"
echo "[run_dev] AUTH: api=$AUTH_API_KEY_ENABLED jwt=$AUTH_JWT_ENABLED mtls=$AUTH_MTLS_ENABLED"
echo "[run_dev] API_KEYS_JSON=$API_KEYS_JSON"

exec $PY_BIN main.py

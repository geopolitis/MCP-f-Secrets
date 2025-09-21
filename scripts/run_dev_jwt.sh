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
import sys

mods = ['fastapi', 'hvac', 'jose']

def has_module(name: str) -> bool:
    try:
        import importlib.util  # type: ignore
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError):
        import pkgutil
        return pkgutil.find_loader(name) is not None

missing = [m for m in mods if not has_module(m)]
sys.stdout.write(' '.join(missing))
PY
)
if [ -n "$MISSING" ]; then
  echo "[run_dev_jwt] Missing deps ($MISSING). Installing requirements..." >&2
  $PY_BIN -m pip install -r requirements.txt
fi

# Minimal env to test JWT auth end-to-end
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-root}
export KV_MOUNT=${KV_MOUNT:-secret}
export DEFAULT_PREFIX=${DEFAULT_PREFIX:-mcp}
# Ensure project root is on PYTHONPATH
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

# Auth toggles: JWT only
export AUTH_API_KEY_ENABLED=${AUTH_API_KEY_ENABLED:-false}
export AUTH_JWT_ENABLED=${AUTH_JWT_ENABLED:-true}
export AUTH_MTLS_ENABLED=${AUTH_MTLS_ENABLED:-false}

# JWT params
export JWT_HS256_SECRET=${JWT_HS256_SECRET:-dev-secret}
export JWT_ISSUER=${JWT_ISSUER:-mcp-auth}
export JWT_AUDIENCE=${JWT_AUDIENCE:-mcp-agents}
# For quick dev you can relax validations:
# export JWT_VALIDATE_ISSUER=false
# export JWT_VALIDATE_AUDIENCE=false

echo "[run_dev_jwt] Using VAULT_ADDR=$VAULT_ADDR"
echo "[run_dev_jwt] AUTH_JWT_ENABLED=$AUTH_JWT_ENABLED JWT_ISSUER=$JWT_ISSUER JWT_AUDIENCE=$JWT_AUDIENCE"

exec $PY_BIN main.py

#!/usr/bin/env bash
set -euo pipefail

# Always run the server with ALL auth methods enabled, regardless of current env.
# - API key: maps dev-api-key -> agent_api
# - JWT: HS256 dev defaults (issuer/audience/secret)
# - mTLS: header-based identity enabled

# Resolve repo root (so script works from any cwd)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
cd "$REPO_ROOT"

# Resolve Python interpreter (prefer venv, then python3)
PY_BIN="python3"
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  PY_BIN="$VIRTUAL_ENV/bin/python"
elif [ -x ".venv/bin/python" ]; then
  PY_BIN=".venv/bin/python"
fi

# Ensure dependencies (including metrics/otel)
MISSING=$($PY_BIN - <<'PY'
import importlib, sys
mods = [
  'fastapi', 'hvac', 'prometheus_client',
  'opentelemetry.api', 'opentelemetry.sdk', 'opentelemetry.instrumentation.fastapi'
]
missing = []
for m in mods:
    try:
        import importlib.util as u
        if u.find_spec(m) is None:
            missing.append(m)
    except Exception:
        # Fallback check
        try:
            __import__(m)
        except Exception:
            missing.append(m)
print(' '.join(missing))
PY
)
if [ -n "$MISSING" ]; then
  echo "[run_all_auth] Installing requirements (missing: $MISSING)..." >&2
  $PY_BIN -m pip install -r requirements.txt
fi

# Vault / server basics
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-root}
export KV_MOUNT=${KV_MOUNT:-secret}
export DEFAULT_PREFIX=${DEFAULT_PREFIX:-mcp}
# Ensure project root is on PYTHONPATH
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

# Force-enable all auth modes
export AUTH_API_KEY_ENABLED=true
export AUTH_JWT_ENABLED=true
export AUTH_MTLS_ENABLED=true

# API key mapping
export API_KEYS_JSON='{"dev-api-key":"agent_api"}'

# JWT defaults
export JWT_HS256_SECRET=${JWT_HS256_SECRET:-dev-secret}
export JWT_ISSUER=${JWT_ISSUER:-mcp-auth}
export JWT_AUDIENCE=${JWT_AUDIENCE:-mcp-agents}
export JWT_VALIDATE_ISSUER=${JWT_VALIDATE_ISSUER:-true}
export JWT_VALIDATE_AUDIENCE=${JWT_VALIDATE_AUDIENCE:-true}

# Optional: JWKS URL for RS256 tokens (can be served by scripts/test_agent_jwt_rs256.sh)
export JWT_JWKS_URL=${JWT_JWKS_URL:-http://127.0.0.1:9001/jwks.json}

echo "[run_all_auth] REPO_ROOT=$REPO_ROOT"
echo "[run_all_auth] VAULT_ADDR=$VAULT_ADDR"
echo "[run_all_auth] auth enabled: api,jwt,mtls"
echo "[run_all_auth] API_KEYS_JSON=$API_KEYS_JSON"
echo "[run_all_auth] JWT_JWKS_URL=$JWT_JWKS_URL"

exec $PY_BIN main.py

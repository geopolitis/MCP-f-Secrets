#!/usr/bin/env bash
set -euo pipefail

# Test RS256/JWKS JWT for agent_jwt without restarting the server.
# Requires the server to have AUTH_JWT_ENABLED=true and JWT_JWKS_URL pointing to our JWKS URL.

BASE_URL=${BASE_URL:-http://127.0.0.1:8089}
JWKS_DIR=${JWKS_DIR:-jwks}
JWKS_PORT=${JWKS_PORT:-9001}
JWKS_URL=${JWKS_URL:-http://127.0.0.1:${JWKS_PORT}/jwks.json}
KID=${KID:-demo}
ISSUER=${JWT_ISSUER:-mcp-auth}
AUDIENCE=${JWT_AUDIENCE:-mcp-agents}
SUB=${SUB:-agent_jwt}
SCOPES_CSV=${SCOPES_CSV:-read,write,delete,list}
PATH1=${PATH1:-scenarios/jwt/demo-rs256}

# Ensure deps
if ! python -c "import jose, http.server" >/dev/null 2>&1; then
  echo "[agent_jwt_rs256] Installing requirements..." >&2
  python -m pip install -r requirements.txt
fi

mkdir -p "$JWKS_DIR"

echo "[agent_jwt_rs256] Generating JWKS (dir=$JWKS_DIR, kid=$KID)"
TOK=$(python3 scripts/gen_rsa_jwks.py --out "$JWKS_DIR" --kid "$KID" \
  --issuer "$ISSUER" --audience "$AUDIENCE" --sub "$SUB" --scopes "$SCOPES_CSV" --ttl 300 --emit-token --reuse-existing)

# Start static JWKS server if not running
if ! lsof -iTCP:${JWKS_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[agent_jwt_rs256] Starting JWKS server on :${JWKS_PORT} (serving $JWKS_DIR)"
  (cd "$JWKS_DIR" && python -m http.server "${JWKS_PORT}" >/dev/null 2>&1 &)
  sleep 0.5
fi

echo "[agent_jwt_rs256] Ensure server uses JWT_JWKS_URL=$JWKS_URL (set this before starting the server)."
echo "[agent_jwt_rs256] whoami"
curl -sS -H "Authorization: Bearer ${TOK}" "${BASE_URL}/whoami" | sed "s/.*/[agent_jwt_rs256] -> &/"

echo "[agent_jwt_rs256] write"
curl -sS -X PUT \
  -H "Authorization: Bearer ${TOK}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"agent":"agent_jwt","alg":"RS256","ok":true}}' \
  "${BASE_URL}/secrets/${PATH1}" | sed "s/.*/[agent_jwt_rs256] -> &/"

echo "[agent_jwt_rs256] read"
curl -sS -H "Authorization: Bearer ${TOK}" "${BASE_URL}/secrets/${PATH1}" | sed "s/.*/[agent_jwt_rs256] -> &/"

echo "[agent_jwt_rs256] done"


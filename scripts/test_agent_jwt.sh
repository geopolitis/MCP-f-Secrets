#!/usr/bin/env bash
set -euo pipefail

# Tests JWT auth for agent_jwt

BASE_URL=${BASE_URL:-http://127.0.0.1:8089}
JWT_SECRET=${JWT_SECRET:-dev-secret}
JWT_ISSUER=${JWT_ISSUER:-mcp-auth}
JWT_AUDIENCE=${JWT_AUDIENCE:-mcp-agents}
SUB=${SUB:-agent_jwt}
SCOPES_CSV=${SCOPES_CSV:-read,write,delete,list}
PATH1=${PATH1:-scenarios/jwt/demo}

if ! python -c "import jose" >/dev/null 2>&1; then
  echo "[agent_jwt] Missing dependency: python-jose. Installing requirements..." >&2
  python -m pip install -r requirements.txt
fi

TOK=$(python3 scripts/gen_jwt.py \
  --secret "${JWT_SECRET}" \
  --issuer "${JWT_ISSUER}" \
  --audience "${JWT_AUDIENCE}" \
  --sub "${SUB}" \
  --scopes "${SCOPES_CSV}" \
  --ttl 300)

echo "[agent_jwt] whoami"
curl -sS -H "Authorization: Bearer ${TOK}" "${BASE_URL}/whoami" | sed 's/.*/[agent_jwt] -> &/'

echo "[agent_jwt] write"
curl -sS -X PUT \
  -H "Authorization: Bearer ${TOK}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"agent":"agent_jwt","ok":true}}' \
  "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_jwt] -> &/'

echo "[agent_jwt] read"
curl -sS -H "Authorization: Bearer ${TOK}" "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_jwt] -> &/'

echo "[agent_jwt] done"


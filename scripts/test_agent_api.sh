#!/usr/bin/env bash
set -euo pipefail

# Tests API key auth for agent_api

BASE_URL=${BASE_URL:-http://127.0.0.1:8089}
API_KEY=${API_KEY:-dev-api-key}
PATH1=${PATH1:-scenarios/api/demo}

echo "[agent_api] whoami"
curl -sS -H "X-API-Key: ${API_KEY}" "${BASE_URL}/whoami" | sed 's/.*/[agent_api] -> &/'

echo "[agent_api] write"
curl -sS -X PUT \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"agent":"agent_api","ok":true}}' \
  "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_api] -> &/'

echo "[agent_api] read"
curl -sS -H "X-API-Key: ${API_KEY}" "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_api] -> &/'

echo "[agent_api] done"


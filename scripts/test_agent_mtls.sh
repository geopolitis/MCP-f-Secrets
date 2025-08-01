#!/usr/bin/env bash
set -euo pipefail

# Tests mTLS header auth for agent_mtls (simulated proxy headers)

BASE_URL=${BASE_URL:-http://127.0.0.1:8089}
DN=${DN:-CN=agent_mtls,OU=dev,O=local}
VERIFY=${VERIFY:-SUCCESS}
PATH1=${PATH1:-scenarios/mtls/demo}

echo "[agent_mtls] whoami"
curl -sS -H "X-SSL-Client-S-DN: ${DN}" -H "X-SSL-Client-Verify: ${VERIFY}" "${BASE_URL}/whoami" | sed 's/.*/[agent_mtls] -> &/'

echo "[agent_mtls] write"
curl -sS -X PUT \
  -H "X-SSL-Client-S-DN: ${DN}" \
  -H "X-SSL-Client-Verify: ${VERIFY}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"agent":"agent_mtls","ok":true}}' \
  "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_mtls] -> &/'

echo "[agent_mtls] read"
curl -sS -H "X-SSL-Client-S-DN: ${DN}" -H "X-SSL-Client-Verify: ${VERIFY}" "${BASE_URL}/secrets/${PATH1}" | sed 's/.*/[agent_mtls] -> &/'

echo "[agent_mtls] done"


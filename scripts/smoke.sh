#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-http://127.0.0.1:8089}
API_KEY=${API_KEY:-dev-api-key}
PATH1=${PATH1:-configs/demo}
TRANSIT_KEY=${TRANSIT_KEY:-mcp}

hdr=(-H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json")

echo "[smoke] Base URL: $BASE_URL, Path: $PATH1"

# Write
RESP=$(curl -sS -X PUT "${BASE_URL}/secrets/${PATH1}" "${hdr[@]}" \
  -d '{"data":{"foo":"bar","n":123}}')
echo "[smoke] WRITE -> $RESP"
VER=$(python3 - <<'PY'
import json,sys
try:
    print(json.load(sys.stdin).get('version',1))
except Exception:
    print(1)
PY
<<< "$RESP")

# Read
curl -sS "${BASE_URL}/secrets/${PATH1}" -H "X-API-Key: ${API_KEY}" | sed 's/.*/[smoke] READ -> &/'

# List
curl -sS "${BASE_URL}/secrets?prefix=$(dirname ${PATH1})" -H "X-API-Key: ${API_KEY}" | sed 's/.*/[smoke] LIST -> &/'

# Delete latest
code=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "${BASE_URL}/secrets/${PATH1}" -H "X-API-Key: ${API_KEY}")
echo "[smoke] DELETE -> HTTP $code"

# Undelete that version
curl -sS -X POST "${BASE_URL}/secrets/${PATH1}:undelete" "${hdr[@]}" \
  -d "{\"versions\":[${VER}]}" | sed 's/.*/[smoke] UNDELETE -> &/'

# Destroy (permanent)
curl -sS -X POST "${BASE_URL}/secrets/${PATH1}:destroy" "${hdr[@]}" \
  -d "{\"versions\":[${VER}]}" | sed 's/.*/[smoke] DESTROY -> &/'

# Transit encrypt/decrypt (hello world)
PT=$(printf 'hello world' | base64)
CIPH=$(curl -sS -X POST "${BASE_URL}/transit/encrypt" "${hdr[@]}" \
  -d "{\"key\":\"${TRANSIT_KEY}\",\"plaintext\":\"${PT}\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("ciphertext",""))')
echo "[smoke] ENCRYPT -> ${CIPH}"

DEC=$(curl -sS -X POST "${BASE_URL}/transit/decrypt" "${hdr[@]}" \
  -d "{\"key\":\"${TRANSIT_KEY}\",\"ciphertext\":\"${CIPH}\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("plaintext",""))')
echo "[smoke] DECRYPT (b64) -> ${DEC}"

if [ "${DEC}" != "${PT}" ]; then
  echo "[smoke] ERROR: transit decrypt mismatch" >&2
  exit 1
fi

echo "[smoke] OK"

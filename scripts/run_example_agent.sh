#!/usr/bin/env bash
set -euo pipefail

# Run the example LangChain MCP agent against a local server.
#
# Usage:
#   bash scripts/run_example_agent.sh [--input 'Write {"foo":"bar"} to configs/demo and read it.'] \
#                                     [--base http://127.0.0.1:8089] \
#                                     [--api-key dev-api-key | --jwt TOKEN | --mtls | --no-llm]
#
# Defaults:
#   --base     http://127.0.0.1:8089
#   --api-key  dev-api-key (if no auth flag supplied)

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
cd "$REPO_ROOT"

INPUT='Write {"foo":"bar"} to configs/demo and read it.'
BASE=${BASE:-http://127.0.0.1:8089}
AUTH_MODE="api"
API_KEY=${API_KEY:-dev-api-key}
JWT_TOKEN=${JWT_TOKEN:-}
MTLS=0
NO_LLM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)
      INPUT=$2; shift 2;;
    --base)
      BASE=$2; shift 2;;
    --api-key)
      AUTH_MODE=api; API_KEY=$2; shift 2;;
    --jwt)
      AUTH_MODE=jwt; JWT_TOKEN=$2; shift 2;;
    --mtls)
      AUTH_MODE=mtls; MTLS=1; shift 1;;
    --no-llm)
      NO_LLM=1; shift 1;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

# Choose Python (prefer repo venv)
PY="python3"
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  PY="$VIRTUAL_ENV/bin/python"
elif [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
fi

# Ensure example deps are present
MISSING=$($PY - <<'PY'
mods=['httpx']
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
  echo "[agent] Installing example requirements..." >&2
  $PY -m pip install -r examples/langchain_agent/requirements.txt
fi

export VAULT_MCP_BASE_URL="$BASE"

if [ "$NO_LLM" = "1" ]; then
  export VAULT_MCP_BASE_URL="$BASE"
  echo "[agent] Running no‑LLM MCP agent against $BASE"
  exec $PY -m examples.langchain_agent.agent_no_llm --base "$BASE" --path configs/no_llm
fi

case "$AUTH_MODE" in
  jwt)
    if [ -z "$JWT_TOKEN" ]; then
      echo "[agent] --jwt requires a token string" >&2; exit 2
    fi
    export VAULT_MCP_BEARER_TOKEN="$JWT_TOKEN"
    echo "[agent] Running JWT agent against $BASE"
    exec $PY -m examples.langchain_agent.agent_mcp_jwt --input "$INPUT"
    ;;
  mtls)
    # Simulate proxy-terminated mTLS via headers
    export VAULT_MCP_MTLS_DN=${VAULT_MCP_MTLS_DN:-CN=agent_mtls,OU=dev}
    export VAULT_MCP_MTLS_VERIFY=${VAULT_MCP_MTLS_VERIFY:-SUCCESS}
    echo "[agent] Running mTLS header agent against $BASE"
    exec $PY -m examples.langchain_agent.agent_mcp_mtls --input "$INPUT"
    ;;
  api|*)
    export VAULT_MCP_API_KEY="$API_KEY"
    echo "[agent] Running API-key agent against $BASE (key=$API_KEY)"
    exec $PY -m examples.langchain_agent.agent --input "$INPUT"
    ;;
esac

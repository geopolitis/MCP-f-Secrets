LangChain Test Agent for Vault MCP

Overview
- A simple LangChain tool-calling agent that manages secrets via your Vault MCP FastAPI server.
- Uses HTTP endpoints exposed by the server; auth via `X-API-Key` or `Authorization: Bearer`.

Setup
1) Install deps (prefer a fresh venv):
   - `python -m venv .venv && source .venv/bin/activate`
   - `pip install -r requirements.txt`
2) Configure environment:
   - `export VAULT_MCP_BASE_URL=http://localhost:8000`
   - For API key: `export VAULT_MCP_API_KEY=your-dev-key`
     - Ensure the server has `API_KEYS_JSON='{"your-dev-key":"agentA"}'`
   - Or for JWT: `export VAULT_MCP_BEARER_TOKEN=...`
   - LLM: `export OPENAI_API_KEY=...` and optionally `OPENAI_MODEL=gpt-4o-mini`

Run
- `python agent.py --input "Create a secret at configs/demo with {\"foo\":\"bar\"} then read it back."`

Notes
- The agent wraps HTTP endpoints as LangChain tools; it does not use the MCP wire protocol directly.
- Tools available: secret_write, secret_read, secret_delete, secret_list, secret_undelete, secret_destroy, transit_encrypt, transit_decrypt.
- The tool outputs avoid printing full secret contents by default; adjust the agent/tools if you want raw values surfaced.


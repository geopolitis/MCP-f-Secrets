Vault MCP Bridge

Overview
- FastAPI-based MCP server that manages agent-scoped secrets in HashiCorp Vault.
- Authentication options: API Key, JWT (HS256), and mTLS via reverse-proxy headers.
- Per-agent namespacing under KV v2; optional Transit encrypt/decrypt.
- Optional per-request child token issuance bound to per-agent policies.
- Simple in-memory rate limiting per agent.

Run
- Install deps:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `python -m pip install -r requirements.txt`
- Easiest (no uvicorn target syntax): `python main.py`
  - Optional env: `HOST=0.0.0.0 PORT=8089 RELOAD=true LOG_LEVEL=debug python main.py`
- Or with uvicorn explicitly:
  - `python -m uvicorn main:app --reload`
  - `python -m uvicorn vault_mcp.app:create_app --factory --reload`

Configuration (env)
- Vault:
  - `VAULT_ADDR` (default: http://localhost:8200)
  - `VAULT_NAMESPACE` (Enterprise only)
  - `VAULT_TOKEN` or `VAULT_ROLE_ID` + `VAULT_SECRET_ID`
  - `KV_MOUNT` (default: secret)
  - `DEFAULT_PREFIX` (default: mcp)
- Auth enable flags:
  - `AUTH_API_KEY_ENABLED` (default: true)
  - `AUTH_JWT_ENABLED` (default: true)
  - `AUTH_MTLS_ENABLED` (default: false)
- API Keys:
  - `API_KEYS_JSON` JSON map: `{ "<api-key>": "<agent-id>" }`
- JWT (HS256 by default):
  - `JWT_HS256_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`
- mTLS via proxy headers:
  - `MTLS_IDENTITY_HEADER` (default: x-ssl-client-s-dn)
  - `MTLS_VERIFY_HEADER` (default: x-ssl-client-verify)
  - `MTLS_SUBJECT_CN_PREFIX` (default: CN=)
- Child token issuance:
  - `CHILD_TOKEN_ENABLED` (default: false)
  - `CHILD_TOKEN_TTL` (default: 90s)
  - `CHILD_TOKEN_POLICY_PREFIX` (default: mcp-agent-)
- Rate limiting:
  - `RATE_LIMIT_ENABLED` (default: true)
  - `RATE_LIMIT_REQUESTS` (default: 60)
  - `RATE_LIMIT_WINDOW_SECONDS` (default: 60)

Auth Modes
- API Key: send `X-API-Key: <key>`. Map keys to agents via `API_KEYS_JSON`.
- JWT: send `Authorization: Bearer <token>` with claims `sub` and optional `scopes`.
- mTLS: terminate TLS at proxy and pass DN with `X-SSL-Client-S-DN`; CN is extracted as subject.

Agent Path Namespace
- Secrets are stored under: `{KV_MOUNT}/data/{DEFAULT_PREFIX}/{subject}/...` (KV v2)
- The server enforces a safe relative path under the agent prefix.

Child Token Issuance
- When `CHILD_TOKEN_ENABLED=true`, the server mints a child token per request bound to a per-agent policy named `{CHILD_TOKEN_POLICY_PREFIX}{subject}` with TTL `CHILD_TOKEN_TTL` and uses it for Vault operations.
- Ensure the policy exists in Vault (see Policy section) and the parent token has capability to create child tokens.

Policy
- Generate HCL for an agent:
  - `python scripts/gen_policy.py --agent alice --mount secret --prefix mcp > alice.hcl`
  - Suggested policy name: `mcp-agent-alice`
- Example HCL (what the script prints):
  - Grants create/read/update/delete/list on `data/{prefix}/{agent}/*`
  - Grants read/list on `metadata/{prefix}/{agent}/*`
  - Grants update on `delete/`, `undelete/`, `destroy/` endpoints for versioned ops
- Apply the policy (manual steps using Vault CLI):
  - `vault policy write mcp-agent-alice alice.hcl`

Endpoints
- KV v2:
  - PUT `/secrets/{path}` — write (scope: write)
  - GET `/secrets/{path}` — read (scope: read) [optional `version`]
  - DELETE `/secrets/{path}` — delete latest version (scope: delete)
  - GET `/secrets?prefix=...` — list keys under prefix (scope: list)
  - POST `/secrets/{path}:undelete` — body `{ "versions": [1,2] }` (scope: write)
  - POST `/secrets/{path}:destroy` — body `{ "versions": [1,2] }` (scope: write)
- Transit:
  - POST `/transit/encrypt` — `{ "key": "k", "plaintext": "<b64>" }` (scope: write)
  - POST `/transit/decrypt` — `{ "key": "k", "ciphertext": "..." }` (scope: read)
- Health/Debug:
  - GET `/healthz`, GET `/whoami`, GET `/echo-headers`
- MCP:
  - Mounted at `/mcp` via `fastapi_mcp` if available

Security Notes
- Enable TLS end-to-end; for mTLS, terminate at a trusted proxy and pass identity headers.
- Do not log secret values; add structured logs with redaction if you extend logging.
- Prefer JWT or mTLS in production; use API keys for dev only.
- Consider enabling Vault audit devices and minimal TTLs for tokens.

Troubleshooting
- Import errors (e.g., No module named fastapi): ensure you run uvicorn with the same Python that installed deps:
  - `python -m uvicorn main:app --reload` (uses current venv interpreter)
- Can’t import main: use the full target format `<module>:<attribute>` — e.g., `main:app`.
- Bind to a different port/host if needed: `python -m uvicorn main:app --reload --port 8090 --host 0.0.0.0`.
- Increase logs: add `--log-level debug --access-log`.

Dev helpers
- Start server with sensible dev env: `bash scripts/run_dev.sh`
- Smoke test (requires server + local Vault dev): `bash scripts/smoke.sh`
- Auth tests (by agent):
  - API key (agent_api): `bash scripts/test_agent_api.sh`
  - JWT (agent_jwt via HS256): `bash scripts/test_agent_jwt.sh` (or generate token with `scripts/gen_jwt.py`)
  - JWT (agent_jwt via RS256/JWKS): `bash scripts/test_agent_jwt_rs256.sh` (serves JWKS locally on :9001)
  - mTLS headers (agent_mtls): `bash scripts/test_agent_mtls.sh`

Always enable all auth
- Start server with all auth methods enabled, regardless of existing env:
  - `bash scripts/run_all_auth.sh`

Three-agent scenario (no restarts)
- Provision Vault with policies for agent_api, agent_jwt, agent_mtls:
  - `cd local-vault && AGENTS=agent_api,agent_jwt,agent_mtls docker compose up -d && cd ..`
- Start server with all auth enabled: `bash scripts/run_all_auth.sh`
- Test each agent independently (in another terminal):
  - API key (agent_api): `bash scripts/test_agent_api.sh`
  - JWT (agent_jwt): `bash scripts/test_agent_jwt.sh`
  - mTLS headers (agent_mtls): `bash scripts/test_agent_mtls.sh`

Vault MCP Bridge

Overview
- FastAPI MCP-compatible server that manages agent-scoped secrets and crypto via HashiCorp Vault.
- Auth: API Key, JWT (HS256 and RS256/JWKS), and mTLS via reverse-proxy headers.
- Per-agent namespacing in KV v2; Transit support (encrypt/decrypt/sign/verify/rewrap/random).
- Optional per-request child token issuance bound to per-agent policies; simple per-agent rate limiting.
- Prometheus metrics at `/metrics` and optional OpenTelemetry tracing.

Quickstart
- Python env:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `python -m pip install -r requirements.txt`
- Start local Vault (dev) for testing:
  - `cd local-vault && docker compose up -d && cd ..`
  - This provisions KV v2 at `secret/`, a Transit key, and example policies. See `local-vault/README.md`.
- Run server:
  - Easiest: `python main.py` (env: `HOST=0.0.0.0 PORT=8089 RELOAD=true LOG_LEVEL=debug`)
  - Or: `python -m uvicorn main:app --reload`
  - Or factory: `python -m uvicorn vault_mcp.app:create_app --factory --reload`
- Helper: `scripts/run_dev_jwt.sh` starts the app with Vault + JWT defaults (no manual env export).
- Sanity checks:
  - `curl http://127.0.0.1:8089/healthz`
  - `bash scripts/smoke.sh` (expects local Vault and default dev auth)
- Vault access (required before running the server):
  - Set credentials so the app can authenticate to Vault, e.g. for the bundled dev compose stack:
    ```bash
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=root   # replace with your own token or AppRole
    ```
  - Without these env vars (or the AppRole equivalents) `/readyz` will return 503 and observability/secret routes will be unauthorized.
  - To avoid re-exporting each run you can `source config/dev-jwt.env` (new sample file) before launching, or use `scripts/run_dev_jwt.sh` which applies the same defaults automatically.
- Optional admin UI:
  - `python3 -m venv .ui-venv && source .ui-venv/bin/activate`
  - `pip install -r ui/requirements.txt`
  - `streamlit run ui/streamlit_app.py`
  - Use the **Manage Subjects & Keys** page to manage `config/users.json`, rotate credentials, and sync profiles to the sidebar.
  - JWT helpers in the UI require `JWT_HS256_SECRET` to be set before launch (e.g., `source config/dev-jwt.env` or run `scripts/run_dev_jwt.sh`).

JWT quickstart (HS256):
- Install helper deps: `pip install 'python-jose[cryptography]'`
- Generate a token with the bundled script (adjust subject/scopes as needed):
  - ```
    python scripts/gen_jwt.py \
      --secret dev-secret \
      --issuer mcp-auth \
      --audience mcp-agents \
      --sub agent_api \
      --scopes read,write,delete,list \
      --ttl 600
    ```
- Use the printed value as the `Authorization: Bearer <token>` header when calling the API or configuring the Streamlit console.

Features
- KV v2 secret CRUD with per-agent prefixes and safe pathing.
- Transit: encrypt/decrypt, sign/verify, rewrap, and random bytes (base64/hex).
- Database: dynamic credentials issuance and lease management.
- SSH: OTP credential and SSH certificate signing.
- Auth: API Key, JWT (HS256 or RS256 via JWKS), mTLS via headers.
- Child tokens per request (optional); per-agent in-memory rate limiting.
- MCP: JSON-RPC over HTTP at `POST /mcp/rpc` (with `GET /mcp/sse` keepalive channel) and stdio transport via `scripts/mcp_stdio.py`.
- Streamlit operations hub: tabs for Secrets, Transit, Database leases (issue/renew/revoke), SSH OTP/signing, and direct MCP tool calls.
- Streamlit agent admin: create multiple AI agent profiles, toggle LLM usage, assign credentials (linked user/API key/JWT), define tasks, and monitor progress/status.
- MCP lifecycle: `initialize`, `tools/list`, `resources/list`, `prompts/list`, `tools/call`, `shutdown`. Protocol version: `2025-06-18`.
- Tools exposed (with required scopes):
  - KV: `kv.read` (read, supports `version`), `kv.write` (write), `kv.list` (list), `kv.delete` (delete), `kv.undelete` (write), `kv.destroy` (write)
  - Transit: `transit.encrypt` (write), `transit.decrypt` (read), `transit.sign` (write), `transit.verify` (read), `transit.rewrap` (write), `transit.random` (read)
  - DB: `db.issue_creds` (write), `db.renew` (write), `db.revoke` (write)
  - SSH: `ssh.otp` (write), `ssh.sign` (write)
- Observability endpoints: `/observability/summary` (Vault/API status + in-flight requests) and `/observability/logs/{requests|responses|server}` (tail JSON logs, read scope required).
- Metrics at `/metrics`; optional OpenTelemetry via OTLP HTTP exporter.

Resources
- Scheme `kv://{subject}/{path}` with optional `?version=N`.
- `resources/list`: advertises `kv://{subject}/` (KV root) for the authenticated subject.
- `resources/get`:
  - `kv://{subject}/foo/bar` returns `{ data, version }` (JSON) for that KV path.
  - `kv://{subject}/foo/` (trailing slash) returns `{ keys: [...] }` listing under that prefix.
  - Cross-subject access is forbidden.

Prompts
- `prompts/list`: returns prompt specs for `kv_read` and `kv_write` with input schemas.
- `prompts/get`:
  - `kv_read`: returns example `messages` and a `suggested_tool` call for `kv.read`.
  - `kv_write`: returns example `messages` and a `suggested_tool` call for `kv.write`.

Configuration (env)
- Vault:
  - `VAULT_ADDR` (default: http://localhost:8200)
  - `VAULT_NAMESPACE` (Enterprise only)
  - `VAULT_TOKEN` or `VAULT_ROLE_ID` + `VAULT_SECRET_ID`
  - `KV_MOUNT` (default: secret)
  - `DEFAULT_PREFIX` (default: mcp)
- Config file (optional, no .env needed):
  - Set `APP_CONFIG_FILE` to a JSON/TOML/YAML file path. Example defaults auto-detected from CWD: `config.toml`, `config.json`, `config.yaml`.
  - Environment variables always override file values.
  - Note: `.env` files are not auto-loaded anymore.
  - Precedence: runtime args (where applicable) → environment variables → `APP_CONFIG_FILE`/auto-detected config → built-in defaults.
- Auth enable flags:
  - `AUTH_API_KEY_ENABLED` (default: true)
  - `AUTH_JWT_ENABLED` (default: true)
  - `AUTH_MTLS_ENABLED` (default: false)
  - CLI helper: `scripts/manage_user.py create <subject>` writes metadata to `config/users.json` and prints policy/API key export commands.
  - UI helper: in Streamlit, check “Generate JWT token” to issue a token during user creation. Generation failures show inline errors and the user entry is not written.
- API Keys:
  - `API_KEYS_JSON` JSON map: `{ "<api-key>": "<agent-id>" }`
- JWT:
  - Common: `JWT_ISSUER` (default: mcp-auth), `JWT_AUDIENCE` (default: mcp-agents)
  - HS256: `JWT_HS256_SECRET`
  - RS256/JWKS: `JWT_JWKS_URL` or `JWT_JWKS_FILE`, `JWT_JWKS_CACHE_SECONDS` (default: 300), `JWT_REQUIRE_KID` (default: false)
  - Validation toggles: `JWT_VALIDATE_ISSUER` (default: true), `JWT_VALIDATE_AUDIENCE` (default: true)
  - Helper: `python scripts/gen_jwt.py --secret <JWT_HS256_SECRET> --sub <agent>` for quick dev tokens (see Quickstart example above).
  - Metadata persisted per user: `jwt_created_at`, `jwt_expires_at`, `jwt_ttl_seconds`. The Streamlit **Current users** grid surfaces status, timestamps, TTL seconds, and offers CSV export.
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
- Server behavior:
  - `HOST`, `PORT`, `RELOAD`, `LOG_LEVEL` for `python main.py`
  - Logs directory: `LOG_DIR` (default: `./logs`)
  - `EXPOSE_REST_ROUTES` (default: true) — when false, disables REST feature routers (`/secrets`, `/transit`, `/db`, `/ssh`, `/whoami`) for MCP‑only deployments.
- Observability:
  - Prometheus at `/metrics` (always enabled)
  - OpenTelemetry: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` (optional)

Auth Modes
- API Key: send `X-API-Key: <key>`. Map keys to agents via `API_KEYS_JSON`.
- JWT: send `Authorization: Bearer <token>` with `sub` and optional `scopes`.
- mTLS: terminate TLS at proxy and pass DN via `X-SSL-Client-S-DN`; CN is used as subject.

Agent Path Namespace
- Secrets live under `{KV_MOUNT}/data/{DEFAULT_PREFIX}/{subject}/...` (KV v2). The server enforces safe relative paths within the agent prefix.

Child Token Issuance
- If `CHILD_TOKEN_ENABLED=true`, a child token is minted per request with policy `{CHILD_TOKEN_POLICY_PREFIX}{subject}` and TTL `CHILD_TOKEN_TTL`.
- Ensure the policy exists and the parent token can create child tokens.

Policy
- Generate HCL for an agent:
  - `python scripts/gen_policy.py --agent alice --mount secret --prefix mcp > alice.hcl`
  - Suggested policy name: `mcp-agent-alice`
- The policy grants CRUD/list on `data/{prefix}/{agent}/*`, list/read on `metadata/{prefix}/{agent}/*`, and versioned ops on delete/undelete/destroy.
- Apply with the Vault CLI: `vault policy write mcp-agent-alice alice.hcl`

Endpoints
- KV v2
  - PUT `/secrets/{path}` — write (scope: write)
  - GET `/secrets/{path}` — read (scope: read) [query `version` optional]
  - DELETE `/secrets/{path}` — delete latest version (scope: delete)
  - GET `/secrets?prefix=...` — list keys (scope: list)
  - POST `/secrets/{path}:undelete` — body `{ "versions": [1,2] }` (scope: write)
  - POST `/secrets/{path}:destroy` — body `{ "versions": [1,2] }` (scope: write)
- Transit
  - POST `/transit/encrypt` — `{ "key": "k", "plaintext": "<b64>" }` (scope: write)
  - POST `/transit/decrypt` — `{ "key": "k", "ciphertext": "..." }` (scope: read)
  - POST `/transit/sign` — `{ key, input, hash_algorithm?, signature_algorithm? }` (scope: write)
  - POST `/transit/verify` — `{ key, input, signature, hash_algorithm? }` (scope: read)
  - POST `/transit/rewrap` — `{ key, ciphertext }` (scope: write)
  - GET `/transit/random?bytes=32&format=base64|hex` (scope: read)
- Database
  - POST `/db/creds/{role}` — issue dynamic DB creds (scope: write)
  - POST `/db/renew` — `{ lease_id, increment? }` (scope: write)
  - POST `/db/revoke` — `{ lease_id }` (scope: write)
- SSH
  - POST `/ssh/otp` — `{ role, ip, username, port? }` (scope: write)
  - POST `/ssh/sign` — `{ role, public_key, cert_type?, valid_principals?, ttl? }` (scope: write)
- Health/Debug/Metrics
  - GET `/healthz`, `/livez`, `/readyz`, `/whoami`, `/echo-headers`, `/metrics`
- MCP
  - Mounted at `/mcp` when `fastapi-mcp` is available

API Docs
- Swagger UI: `http://127.0.0.1:8089/docs`
- ReDoc: `http://127.0.0.1:8089/redoc`
- OpenAPI: `http://127.0.0.1:8089/openapi.json`

MCP Usage
- HTTP JSON-RPC: `POST /mcp/rpc` with JSON-RPC 2.0 messages; authenticate same as REST (API key / JWT / mTLS).
- SSE channel: `GET /mcp/sse` provides periodic keepalives for server→client messaging (placeholder; extend as needed).
- stdio: `SUBJECT=agentA python scripts/mcp_stdio.py` and write newline-delimited JSON-RPC messages to stdin.
- Initialize result includes `protocolVersion: 2025-06-18`, basic capabilities, and lists tools/resources/prompts.
 - SSE events: server emits `tool.completed` events with `{type, tool, subject, ts}`; keepalives every 15s.

MCP Inspector
- An official, interactive UI for MCP servers (Swagger-like, but for MCP) that discovers tools/resources/prompts and lets you call them live.
- Connect via HTTP:
  - RPC URL: `http://127.0.0.1:8089/mcp/rpc`
  - SSE URL (optional): `http://127.0.0.1:8089/mcp/sse`
  - Auth headers: add `X-API-Key: dev-api-key` (or `Authorization: Bearer <JWT>`) in the Inspector’s connection settings.
  - If connecting from the hosted Inspector (HTTPS) to your local HTTP server, enable CORS:
    - `export CORS_ALLOW_ORIGINS=https://inspector.modelcontextprotocol.io`
    - Consider exposing your server via HTTPS (e.g., ngrok) to avoid mixed-content blocking.
- Or connect via stdio:
  - Command: `SUBJECT=agent_api python scripts/mcp_stdio.py`
  - Inspector will spawn the process and speak JSON-RPC over stdio.
- Once connected, Inspector should list the available tools: `kv.read`, `kv.write`, `kv.list`, `kv.delete`, `kv.undelete`, `kv.destroy`.
- Current state: Resources/Prompts are empty; SSE sends keepalives only.

Troubleshooting Inspector
- `ModuleNotFoundError: vault_mcp` when running stdio: ensure you run from repo root, or use `SUBJECT=agent_api PYTHONPATH=$(pwd) python scripts/mcp_stdio.py`. The script now auto-adds repo root to `sys.path`.
- CORS errors in the browser: set `CORS_ALLOW_ORIGINS=https://inspector.modelcontextprotocol.io` (comma separate multiple origins) and restart the server.
- Mixed content blocked: use an HTTPS tunnel to your local server (e.g., `ngrok http 8089`) and switch Inspector URLs to `https`.

Prometheus & OpenTelemetry
- Prometheus endpoint: `GET /metrics` (text). Quick check: `curl -s http://127.0.0.1:8089/metrics | head`.
- Metrics include `http_requests_total` and `http_request_duration_seconds` with labels `method`, `route`, `status`.
- Additional telemetry: `http_requests_with_correlation_total` counts requests that include or receive a correlation ID. Every HTTP response returns `X-Correlation-Id`; if OTEL tracing is enabled, `X-Trace-Id` is also emitted.
- OpenTelemetry tracing (optional): set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g., `http://localhost:4318/v1/traces`) and `OTEL_SERVICE_NAME` (default: `vault-mcp`).
- Structured logs: JSON files under `./logs/` (`requests.log`, `responses.log`, `server.log`). Tail with `tail -f logs/requests.log`.

Logging Details
- Format: newline-delimited JSON. Core fields: `ts`, `lvl`, `msg`, `logger` plus context in `extra`.
- Request logs (`vault_mcp.request`): include `request_id`, `client`, `method`, `path`, `status`, `duration_ms`.
- Response/event logs (`vault_mcp.response`): per-endpoint keys, e.g.,
  - `kv_put|kv_get|kv_delete`: `subject`, `path`, `keys`, `version`, `request_id`
  - `kv_list`: `subject`, `prefix`, `count`, `request_id`
  - `transit_*`: `subject`, `key`, size/validity hints, `request_id`
  - `db_*` and `ssh_*`: high-level descriptors (e.g., `role`, `lease_id_suffix`, `ip`, `user`), never secret values
- Request ID: responses include `X-Request-Id`; it is echoed in logs for correlation.
- Example request log line:
  - `{ "ts": "2024-01-01T10:00:00", "lvl": "info", "msg": "request", "logger": "vault_mcp.request", "request_id": "...", "client": "127.0.0.1", "method": "GET", "path": "/secrets", "status": 200, "duration_ms": 12 }`

Examples (curl)
- Write then read a secret (API key `dev-key` for agent `agent_api`):
  - `curl -X PUT -H 'X-API-Key: dev-key' -H 'Content-Type: application/json' \
     -d '{"data": {"foo":"bar"}}' http://127.0.0.1:8089/secrets/configs/demo`
  - `curl -H 'X-API-Key: dev-key' http://127.0.0.1:8089/secrets/configs/demo`
- Random bytes from Transit (hex):
  - `curl -H 'X-API-Key: dev-key' 'http://127.0.0.1:8089/transit/random?bytes=16&format=hex'`
- RS256/JWKS quick test:
  - See `local-vault/jwks/README.md` for generating keys, running JWKS, and testing.

Local Dev Helpers
- Start server with sensible dev env: `bash scripts/run_dev.sh`
- Enable all auth regardless of current env: `bash scripts/run_all_auth.sh`
- Smoke test (server + local Vault): `bash scripts/smoke.sh`
- Auth tests by agent:
  - API key (agent_api): `bash scripts/test_agent_api.sh`
  - JWT HS256 (agent_jwt): `bash scripts/test_agent_jwt.sh`
  - JWT RS256/JWKS (agent_jwt): `bash scripts/test_agent_jwt_rs256.sh`
  - mTLS headers (agent_mtls): `bash scripts/test_agent_mtls.sh`

End-to-End and Example Agents
- One-shot E2E (server + MCP HTTP + stdio + optional REST):
  - `LOG_LEVEL=DEBUG bash scripts/e2e_local.sh`
- Example MCP agents (HTTP JSON-RPC):
  - API key: `bash scripts/run_example_agent.sh`
  - JWT: `bash scripts/run_example_agent.sh --jwt 'YOUR_JWT'`
  - mTLS headers: `bash scripts/run_example_agent.sh --mtls`
  - No‑LLM direct client (no model provider): `bash scripts/run_example_agent.sh --no-llm`

Examples
- LangChain agent that wraps these endpoints as tools:
  - See `examples/langchain_agent/README.md` and `examples/langchain_agent/agent.py`

Testing
- Run tests: `pytest`
- Pytest overview:
  - `tests/test_health.py`: Verifies basic liveness endpoints — `GET /healthz` and `GET /livez` return `ok: true`.
  - `tests/test_auth_and_kv.py`: Exercises API‑key auth and KV v2 CRUD.
    - Uses a mocked hvac KV client to avoid real Vault.
    - Flow: `PUT /secrets/configs/demo` writes data, `GET` reads it back, `DELETE` removes it, subsequent `GET` returns 404.
    - Also checks `GET /whoami` returns the expected subject for `X-API-Key`.
  - `tests/test_transit_random.py`: Tests Transit random byte generation endpoint with deterministic mock.
    - Monkeypatches `client_for_principal` to return a stub where `generate_random_bytes` is predictable.
    - Validates both `format=hex` and default `base64` responses for `GET /transit/random`.
  - `tests/test_health_ready.py`: Covers `/readyz` for authenticated, unauthenticated, Vault error, and generic error cases.
  - `tests/test_kv_extras.py`: Covers `GET /secrets?prefix=...` list and version ops (`:undelete`, `:destroy`).
  - `tests/test_transit_endpoints.py`: Covers `/transit/encrypt|decrypt|sign|verify|rewrap` with a transit stub.
  - `tests/test_db_and_ssh_routes.py`: Covers `/db/creds|renew|revoke` and `/ssh/otp|sign` with stubs.
  - `tests/test_auth_modes.py`: HS256 JWT `/whoami` (valid and bad aud), mTLS header success/fail.
  - `tests/test_auth_jwt_rs256_local.py`: Local RS256: generates RSA + JWKS and validates `/whoami` via monkeypatched JWKS.
  - `tests/test_rate_limit_and_metrics.py`: Verifies `/metrics` and rate limiting on `/transit/random` (429 on third call).
  - `tests/test_security_path_and_scopes.py`: Path sanitization and 403 when scopes are insufficient.
  - `tests/test_app_exception_handlers.py`: Maps Vault `Forbidden` -> 403 and `VaultError` -> 502 JSON responses.
  - (If you add MCP client tests) exercise `POST /mcp/rpc` for `initialize`, `tools/list`, and `tools/call` with a JWT or API key.

Run subsets
- Keyword filter: `pytest -k transit`
- Coverage detail: `pytest -q --cov=vault_mcp --cov-report=term-missing`

Security Notes
- Use TLS end-to-end; for mTLS, terminate at a trusted proxy and pass identity headers.
- Avoid logging secret values; the app uses structured logging with response metadata only.
- Prefer JWT or mTLS in production; reserve API keys for development.
- Enable Vault audit devices and keep token TTLs minimal.

Troubleshooting
- Import errors (e.g., fastapi not found): ensure you use the same Python interpreter that installed deps.
  - `python -m uvicorn main:app --reload`
- Uvicorn targets: use `<module>:<attribute>` — e.g., `main:app`.
- Change port/host: `python -m uvicorn main:app --reload --port 8090 --host 0.0.0.0`
- Increase logs: add `--log-level debug --access-log`

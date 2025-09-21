# FastMCP UI User Guide

## 1. Launch the Streamlit Console
1. Create/activate a virtualenv (optional but recommended):
   ```bash
   python3 -m venv .ui-venv
   source .ui-venv/bin/activate
   ```
2. Install UI dependencies: `pip install -r ui/requirements.txt`.
3. Ensure the FastMCP backend is running (`python main.py` or `scripts/run_dev_jwt.sh`).
4. Start Streamlit: `streamlit run ui/streamlit_app.py`.

> Tip: `scripts/run_dev_jwt.sh` exports `JWT_HS256_SECRET` and other defaults so the UI can generate JWTs without manual exports.

## 2. Configure the Sidebar Session
- Enter the FastAPI base URL (default `http://127.0.0.1:8089`).
- Pick a *User profile* (from **Manage Subjects & Keys**) or stay on *Custom*.
- Toggle `Use API Key` / `Use JWT` and paste the secrets (fields are masked).
- Click **Save session**. The snapshot confirms which credentials are active.

Switching to an existing profile auto-loads its API key/JWT and logs last activity for that subject.

## 3. Manage Subjects & Keys
This page lets you provision and rotate Vault-facing credentials.

1. **Current users table**
   - Filter by subject/scope, reorder columns, or export to CSV.
   - Columns show API key, scope list, last active, JWT creation/expiry timestamps, TTL seconds, and status (active/expired/no JWT).
2. **Create new user**
   - Declare subject name, optional description, scopes, and (if needed) auto-generate a JWT.
   - JWT creation only succeeds if `JWT_HS256_SECRET` is set; failures block user creation and display an error.
3. **Edit existing user**
   - Rotate API keys or JWTs; success/failure messages appear inline. When a JWT is near expiry (under 24h), a warning banner is shown.
   - Scope editing uses a multi-select control; credentials are previewed for easy copy/paste.
4. **Delete user**
   - Removes the entry from `config/users.json`. Remember to revoke Vault tokens separately if required.

## 4. Monitor Health & Logs
Use the **Observability** tab to keep an eye on the service:
- **Health** – `/healthz`, `/readyz`, and the `/observability/summary` endpoint (with recent 4xx/5xx counts and in-flight gauge).
- **Metrics** – in-flight requests plus cumulative 4xx/5xx from Prometheus (`/metrics`). Expand to view raw output.
- **Logs** – tail `requests.log`, `responses.log`, or `server.log`. Requires a subject with the `read` scope.

Quick links on the landing page:
- REST docs (`/docs`, `/redoc`, `/openapi.json`).
- MCP endpoints (`POST /mcp/rpc`, `/mcp/sse`) and a pre-filled link to the hosted MCP Inspector.

## 5. Operate Vault Workflows
The **Vault Operations** page provides helper forms across five tabs:

| Tab      | Capabilities |
|----------|--------------|
| Secrets  | Read/write KV entries (with optional version). |
| Transit  | Encrypt/decrypt payloads via Vault Transit. |
| Database | Issue, renew, revoke DB leases. |
| SSH      | Generate one-time passwords or sign public keys. |
| MCP Tools| Invoke any MCP tool by name using JSON arguments (executes `/mcp/rpc`). |

All actions reuse the sidebar credentials, so you can test multiple users by switching profiles.

## 6. Administer AI Agents
The **AI Agent Administration** page manages application-facing agents:

1. **Overview tab** – filter/search agents, inspect LLM usage, credential mode, task counts, and export to CSV.
2. **Import tab** – upload a single agent or an array of agents; valid records persist immediately so you can seed environments in bulk.
3. **Create tab** – define name/description, toggle LLM, select credential mode (linked user/API key/JWT), then click *Create*. 
4. **Manage tab** – pick an agent to update metadata, toggle LLM, adjust credentials, upload task JSON (object or list), add manual tasks, change status/notes, or run tasks. Use the **Danger zone** subtab to delete the agent after explicit confirmation.

All agent data is persisted in `ui/config/agents.json` so the configuration survives restarts, but the repository keeps this directory gitignored so each environment maintains its own state.

## 7. Correlation, Tracing & Metrics
- Every HTTP response carries `X-Correlation-Id`. When OTEL is configured (`OTEL_EXPORTER_OTLP_ENDPOINT`), `X-Trace-Id` accompanies it for cross-system tracing.
- Prometheus exposes `http_requests_with_correlation_total` alongside existing counters/histograms (`/metrics`).

## 8. CLI Helpers & Tests
- Manage users from the CLI: `scripts/manage_user.py create <subject>` outputs API key/JWT and Vault policy instructions.
- Sample agent smoke tests: `scripts/run_example_agent.sh` (API key/JWT/mTLS modes).
- Full regression suite: `pytest` (includes metadata round-trip tests for users/agents, correlation header checks, and server routes).

## 9. Logs & Telemetry Files
- Structured JSON logs are stored under `logs/` (`requests.log`, `responses.log`, `server.log`). Use `tail -f logs/requests.log` for live tracking.
- `config/users.json` and `config/agents.json` persist your UI changes; edit carefully or use the Streamlit pages to modify entries.

With these steps you can provision credentials, build AI agent profiles, execute Vault workflows, and monitor the entire stack through Streamlit.

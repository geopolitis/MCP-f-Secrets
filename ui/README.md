# FastMCP Streamlit Admin

Lightweight Streamlit dashboard for interacting with the FastMCP (FastAPI + MCP bridge) service.

## Setup

```bash
python3 -m venv .ui-venv
source .ui-venv/bin/activate
pip install -r ui/requirements.txt
```

## Run

```bash
streamlit run ui/streamlit_app.py
```

The sidebar lets you configure the service URL and credentials. Use the page tabs for:

- **Admin & Authentication**: sanity-check connectivity with the current credentials and inspect stored session state.
- **Observability**: dashboards for API/Vault health, in-flight request counts, 4xx/5xx totals, and log tailing (requires read scope).
- **Vault Operations**: tabs for Secrets, Transit, Database (issue/renew/revoke leases), SSH (OTP/sign), and direct MCP tool calls.
- **Manage Subjects & Keys**: administer users stored in `config/users.json`, rotate API keys/JWTs, and sync profiles with the sidebar.
- **AI Agent Administration**: manage agent profiles stored in `config/agents.json`, assign credentials (linked subjects/API keys/JWTs), toggle LLM usage, and create/update task queues per agent.

Notes:
- JWT tooling requires `JWT_HS256_SECRET` to be set before launching the UI (`source config/dev-jwt.env` or run `scripts/run_dev_jwt.sh`).
- The **Current users** table supports filtering, CSV export, and displays JWT metadata (created/expiry/TTL/status).
- Vault Operations actions reuse the REST/MCP APIs and will surface detailed success/failure notifications.

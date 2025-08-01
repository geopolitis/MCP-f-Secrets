Local Vault (Dev) via Docker Compose

Overview
- Starts a Vault dev server using the official `hashicorp/vault:latest` image.
- Enables KV v2 at `secret/` and the Transit engine; creates a sample transit key and a per-agent policy.
- Intended for local testing with this MCP server.

Files
- `docker-compose.yml`: Vault dev + setup container
- `setup/setup.sh`: Idempotent provisioning (KV v2, Transit, policy)

Usage
1) From this folder:
   - `export VAULT_DEV_ROOT_TOKEN_ID=root` (optional; defaults to `root`)
   - Optional env overrides:
     - Set agents to provision: `export AGENTS=agent_api,agent_jwt,agent_mtls`
     - `export KV_MOUNT=secret` (default)
     - `export PREFIX=mcp` (default)
     - `export TRANSIT_KEY=mcp` (default)
2) Start:
   - `docker compose up -d`
3) Verify:
   - `curl http://127.0.0.1:8200/v1/sys/health`
   - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN_ID:-root} vault secrets list`
4) App env to use:
   - `export VAULT_ADDR=http://127.0.0.1:8200`
   - `export VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN_ID:-root}`
   - Enable all auth for testing: use `scripts/run_dev.sh` from repo root (sets API key for agent_api, JWT defaults, and enables mTLS headers)

Notes
- This runs Vault in dev mode (in-memory, single unseal key, single root token). DO NOT use in production.
- The setup container is idempotent; re-running compose will recreate the policy/key if needed.
- To inspect policies: `VAULT_ADDR=... VAULT_TOKEN=... vault policy read mcp-agent-agent_api` (and agent_jwt, agent_mtls)

import os
import httpx


def mtls_client() -> httpx.Client:
    base = os.environ.get("VAULT_MCP_BASE_URL", "http://127.0.0.1:8089")
    dn = os.environ.get("VAULT_MCP_MTLS_DN", "CN=agent_mtls")
    verify = os.environ.get("VAULT_MCP_MTLS_VERIFY", "SUCCESS")
    headers = {"X-SSL-Client-S-DN": dn, "X-SSL-Client-Verify": verify, "Content-Type": "application/json"}
    return httpx.Client(base_url=base, headers=headers, timeout=10.0)


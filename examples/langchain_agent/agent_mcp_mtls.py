#!/usr/bin/env python3
import os
os.environ.setdefault("VAULT_MCP_BASE_URL", "http://127.0.0.1:8089")
# Simulate mTLS via headers expected by the server (proxy-terminated mTLS)
os.environ.setdefault("VAULT_MCP_MTLS_DN", "CN=agent_mtls,OU=dev")
os.environ.setdefault("VAULT_MCP_MTLS_VERIFY", "SUCCESS")

from .agent_mtls_support import mtls_client
from .agent import build_agent


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="Write a secret at configs/mtls with {\"ok\":true} then read it.")
    args = ap.parse_args()

    # Swap the global client used by agent.py to one with mTLS headers
    import examples.langchain_agent.agent as base
    base.client = mtls_client()

    ex = build_agent()
    print(ex.invoke({"input": args.input}))


#!/usr/bin/env python3
import os
os.environ.setdefault("VAULT_MCP_BASE_URL", "http://127.0.0.1:8089")
# Expect VAULT_MCP_BEARER_TOKEN from env; fallback to printing guidance

from .agent import build_agent  # reuses MCP-enabled tools


if __name__ == "__main__":
    import argparse
    tok = os.environ.get("VAULT_MCP_BEARER_TOKEN")
    if not tok:
        print("[warn] VAULT_MCP_BEARER_TOKEN not set; set a JWT to test JWT auth.")
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="Write a secret at configs/jwt with {\"ok\":true} then read it.")
    args = ap.parse_args()
    ex = build_agent()
    print(ex.invoke({"input": args.input}))


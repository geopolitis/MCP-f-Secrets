#!/usr/bin/env python3
"""
Minimal, no‑LLM MCP client that calls tools directly over HTTP JSON‑RPC.

Usage:
  VAULT_MCP_BASE_URL=http://127.0.0.1:8089 \
  VAULT_MCP_API_KEY=dev-api-key \
  python -m examples.langchain_agent.agent_no_llm --path configs/no_llm --data '{"foo":"bar"}'

Or with bearer token:
  VAULT_MCP_BEARER_TOKEN=... python -m examples.langchain_agent.agent_no_llm --path configs/no_llm
"""
import os
import json
import argparse
import httpx


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    api = os.environ.get("VAULT_MCP_API_KEY")
    tok = os.environ.get("VAULT_MCP_BEARER_TOKEN")
    if api:
        h["X-API-Key"] = api
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def rpc(client: httpx.Client, base: str, body: dict) -> dict:
    r = client.post(base.rstrip("/") + "/mcp/rpc", json=body, headers=_headers(), timeout=10.0)
    r.raise_for_status()
    js = r.json()
    if "error" in js:
        raise RuntimeError(js["error"])
    return js.get("result") or {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("VAULT_MCP_BASE_URL", "http://127.0.0.1:8089"))
    ap.add_argument("--path", default="configs/no_llm")
    ap.add_argument("--data", default='{"foo":"bar"}', help="JSON string for write")
    args = ap.parse_args()

    data_obj = json.loads(args.data)

    with httpx.Client() as client:
        print("[no-llm] initialize")
        print(rpc(client, args.base, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}))

        print("[no-llm] tools/list")
        tools = rpc(client, args.base, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        print([t.get("name") for t in tools.get("tools", [])])

        print(f"[no-llm] kv.write {args.path}")
        wr = rpc(
            client,
            args.base,
            {"jsonrpc": "2.0", "id": "w1", "method": "tools/call", "params": {"name": "kv.write", "arguments": {"path": args.path, "data": data_obj}}},
        )
        print(wr)

        print(f"[no-llm] kv.read {args.path}")
        rd = rpc(
            client,
            args.base,
            {"jsonrpc": "2.0", "id": "r1", "method": "tools/call", "params": {"name": "kv.read", "arguments": {"path": args.path}}},
        )
        print(rd)


if __name__ == "__main__":
    main()


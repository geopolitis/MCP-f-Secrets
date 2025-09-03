#!/usr/bin/env python3
"""
HTTP JSON-RPC smoke tester for the MCP server.

Usage:
  python scripts/mcp_http_smoke.py [--base http://127.0.0.1:8089] [--path configs/demo] [--mode basic|full]

Auth (one of):
  - API key (default): export API_KEY=dev-api-key
  - Bearer: export BEARER_TOKEN=...

Modes:
  - basic: initialize + tools/list
  - full:  initialize + tools/list + kv.write + kv.read + kv.list + kv.delete

Exits non-zero on failures. Prints concise results.
"""
import argparse
import os
import sys
import json
import httpx


def _hdrs():
    h = {"Content-Type": "application/json"}
    api_key = os.environ.get("API_KEY")
    bearer = os.environ.get("BEARER_TOKEN")
    if api_key:
        h["X-API-Key"] = api_key
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    if not api_key and not bearer:
        h["X-API-Key"] = "dev-api-key"
    return h


def _rpc(client: httpx.Client, base: str, body: dict) -> httpx.Response:
    url = base.rstrip("/") + "/mcp/rpc"
    return client.post(url, json=body, headers=_hdrs(), timeout=10.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("BASE_URL", "http://127.0.0.1:8089"))
    ap.add_argument("--path", default=os.environ.get("KV_PATH", "configs/demo"))
    ap.add_argument("--mode", choices=["basic", "full"], default=os.environ.get("MODE", "basic"))
    args = ap.parse_args()

    ok = True
    # verify=False avoids importing certifi on some broken local setups; fine for HTTP
    with httpx.Client(verify=False, trust_env=False) as client:
        # initialize
        r = _rpc(client, args.base, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        if r.status_code != 200:
            print(f"[init] HTTP {r.status_code}")
            return 2
        ver = r.json().get("result", {}).get("protocolVersion")
        print(f"[init] protocolVersion={ver}")

        # tools/list
        r = _rpc(client, args.base, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        if r.status_code != 200:
            print(f"[tools] HTTP {r.status_code}")
            return 2
        tools = [t.get("name") for t in r.json().get("result", {}).get("tools", [])]
        print(f"[tools] {tools}")

        if args.mode == "basic":
            return 0

        # full KV roundtrip (requires Vault configured + policy)
        # write
        w = {
            "jsonrpc": "2.0",
            "id": "w1",
            "method": "tools/call",
            "params": {"name": "kv.write", "arguments": {"path": args.path, "data": {"foo": "bar"}}},
        }
        r = _rpc(client, args.base, w)
        if r.status_code != 200 or not (r.json().get("result", {}).get("content", {}).get("ok")):
            print(f"[kv.write] FAIL: {r.status_code} {r.text}")
            return 3
        print("[kv.write] ok")

        # read
        rd = {
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "tools/call",
            "params": {"name": "kv.read", "arguments": {"path": args.path}},
        }
        r = _rpc(client, args.base, rd)
        if r.status_code != 200:
            print(f"[kv.read] HTTP {r.status_code} {r.text}")
            return 3
        content = r.json().get("result", {}).get("content", {})
        if (content.get("data") or {}).get("foo") != "bar":
            print(f"[kv.read] FAIL: {content}")
            return 3
        print("[kv.read] ok")

        # list
        ls = {
            "jsonrpc": "2.0",
            "id": "l1",
            "method": "tools/call",
            "params": {"name": "kv.list", "arguments": {"prefix": os.path.dirname(args.path)}},
        }
        r = _rpc(client, args.base, ls)
        if r.status_code != 200 or os.path.basename(args.path) not in (r.json().get("result", {}).get("content", {}).get("keys") or []):
            print(f"[kv.list] WARN/FAIL: {r.status_code} {r.text}")
        else:
            print("[kv.list] ok")

        # delete
        dl = {
            "jsonrpc": "2.0",
            "id": "d1",
            "method": "tools/call",
            "params": {"name": "kv.delete", "arguments": {"path": args.path}},
        }
        r = _rpc(client, args.base, dl)
        if r.status_code != 200:
            print(f"[kv.delete] HTTP {r.status_code} {r.text}")
            return 3
        print("[kv.delete] ok")

    return 0


if __name__ == "__main__":
    sys.exit(main())

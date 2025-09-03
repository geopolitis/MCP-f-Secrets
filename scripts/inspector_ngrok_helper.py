#!/usr/bin/env python3
"""
Builds an MCP Inspector URL automatically from a running ngrok tunnel.

Prereqs:
- ngrok is installed and running: `ngrok http 8089`
- Server running on http://127.0.0.1:8089

Usage:
  1) Start your server (e.g., `bash scripts/run_all_auth.sh`)
  2) In another shell, start ngrok: `ngrok http 8089`
  3) Run: `python scripts/inspector_ngrok_helper.py`

Outputs a ready-to-open Inspector URL with the ngrok HTTPS domain and API key header prefilled.
"""
import json
import sys
from urllib.request import urlopen
from urllib.parse import quote


def main() -> int:
    try:
        with urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2.0) as resp:
            data = json.load(resp)
    except Exception as e:
        print("[err] failed to query ngrok API at :4040 — is ngrok running?", file=sys.stderr)
        print(f"      {e}", file=sys.stderr)
        return 2

    https_url = None
    for t in data.get("tunnels", []):
        pub = t.get("public_url")
        if pub and pub.startswith("https://"):
            https_url = pub
            break
    if not https_url:
        print("[err] no https public_url found in ngrok tunnels", file=sys.stderr)
        return 2

    rpc = f"{https_url}/mcp/rpc"
    sse = f"{https_url}/mcp/sse"
    headers = '{"X-API-Key":"dev-api-key"}'

    url = (
        "https://inspector.modelcontextprotocol.io/"
        f"?rpc={quote(rpc, safe='')}"
        f"&sse={quote(sse, safe='')}"
        f"&headers={quote(headers, safe='')}"
    )
    print(url)
    return 0


if __name__ == "__main__":
    sys.exit(main())


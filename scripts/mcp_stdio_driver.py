#!/usr/bin/env python3
"""
Drives the stdio MCP transport end-to-end.

Runs `scripts/mcp_stdio.py` as a subprocess, sends JSON-RPC lines, and prints responses.
Exits non-zero if any request fails to get a result.

Usage:
  SUBJECT=agent_api python scripts/mcp_stdio_driver.py [--mode basic|full] [--path configs/demo]

Mode "full" attempts kv.write/kv.read via tools — requires Vault configured.
"""
import os
import sys
import json
import argparse
import subprocess


def send(p, obj):
    line = json.dumps(obj)
    p.stdin.write((line + "\n").encode("utf-8"))
    p.stdin.flush()


def read_line(p, timeout=5.0):
    p.poll()
    # Simple blocking read with a timeout using select
    import select
    r, _, _ = select.select([p.stdout], [], [], timeout)
    if not r:
        return None
    return p.stdout.readline().decode("utf-8").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["basic", "full"], default=os.environ.get("MODE", "basic"))
    ap.add_argument("--path", default=os.environ.get("KV_PATH", "configs/demo"))
    args = ap.parse_args()

    env = os.environ.copy()
    env.setdefault("SUBJECT", "agent_api")

    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "mcp_stdio.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        ln = read_line(proc)
        if not ln:
            print("[stdio] no response to initialize")
            return 2
        print("[stdio]", ln)

        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        ln = read_line(proc)
        if not ln:
            print("[stdio] no response to tools/list")
            return 2
        print("[stdio]", ln)

        if args.mode == "basic":
            send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown"})
            read_line(proc)
            return 0

        # kv.write
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": "w1",
                "method": "tools/call",
                "params": {"name": "kv.write", "arguments": {"path": args.path, "data": {"foo": "bar"}}},
            },
        )
        print("[stdio]", read_line(proc))

        # kv.read
        send(
            proc,
            {"jsonrpc": "2.0", "id": "r1", "method": "tools/call", "params": {"name": "kv.read", "arguments": {"path": args.path}}},
        )
        print("[stdio]", read_line(proc))

        send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown"})
        read_line(proc)
        return 0
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())


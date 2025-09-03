#!/usr/bin/env python3
"""
Minimal stdio JSON-RPC transport for the Vault MCP service.

Reads newline-delimited JSON-RPC 2.0 messages from stdin and writes responses to stdout.

Auth: For demo purposes, subject can be provided via env SUBJECT (granted full scopes).
"""
import json
import os
import sys
from typing import Any, Dict

# Ensure repo root is on sys.path so `vault_mcp` is importable when run directly
THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import asyncio
import logging
from logging.handlers import RotatingFileHandler
try:
    from vault_mcp.mcp_core import _initialize_result, _handle_tool_call_async, MCP_PROTOCOL_VERSION
    from vault_mcp.models import Principal
except Exception as e:
    sys.stderr.write("[mcp_stdio] Failed to import vault_mcp. Run within your venv or install deps.\n")
    sys.stderr.write(f"[mcp_stdio] Import error: {e}\n")
    sys.exit(2)


def _println(obj: Dict[str, Any]):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    subject = os.environ.get("SUBJECT", "stdio-agent")
    p = Principal(subject=subject, scopes=["read", "write", "delete", "list"], vault_path_prefix=f"mcp/{subject}")
    # Setup stdio logger
    log_dir = os.path.join(REPO_ROOT, "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        pass
    logger = logging.getLogger("vault_mcp.stdio")
    if not logger.handlers:
        sh = logging.StreamHandler()
        fh = None
        try:
            fh = RotatingFileHandler(os.path.join(log_dir, "stdio.log"), maxBytes=5_000_000, backupCount=3)
        except Exception:
            fh = None
        for h in filter(None, [sh, fh]):
            logger.addHandler(h)
        lvl = os.environ.get("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, lvl, logging.INFO))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            mid = msg.get("id")
            try:
                logger.debug("stdio_request %s", json.dumps({"id": mid, "method": msg.get("method")}))
            except Exception:
                pass
            if msg.get("jsonrpc") != "2.0":
                _println({"jsonrpc": "2.0", "id": mid, "error": {"code": -32600, "message": "Invalid Request"}})
                continue
            m = msg.get("method")
            if m == "initialize":
                _println({"jsonrpc": "2.0", "id": mid, "result": _initialize_result()})
            elif m == "shutdown":
                _println({"jsonrpc": "2.0", "id": mid, "result": {"ok": True}})
                break
            elif m == "tools/list":
                # Reuse HTTP path; keeping minimal for demo
                from vault_mcp.mcp_core import _tool_schemas
                tools = [{"name": k, **v} for k, v in _tool_schemas().items()]
                _println({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
            elif m == "tools/call":
                params = msg.get("params") or {}
                name = params.get("name"); args = params.get("arguments") or {}
                try:
                    res = asyncio.run(_handle_tool_call_async(name, args, p))
                    _println({"jsonrpc": "2.0", "id": mid, "result": {"content": res}})
                    try:
                        logger.info("stdio_result %s", json.dumps({"id": mid, "tool": name, "status": "ok"}))
                    except Exception:
                        pass
                except Exception as e:
                    _println({"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": str(e)}})
                    try:
                        logger.info("stdio_result %s", json.dumps({"id": mid, "tool": name, "status": "error", "err": str(e)}))
                    except Exception:
                        pass
            else:
                _println({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})
        except Exception as e:
            _println({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}})


if __name__ == "__main__":
    main()

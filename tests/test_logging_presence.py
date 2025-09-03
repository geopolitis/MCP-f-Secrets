import json
import os
import sys
import time
import subprocess


def test_http_request_logging(client, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    r = client.get("/healthz")
    assert r.status_code == 200
    # Find a request log record
    assert any(rec.name == "vault_mcp.request" and rec.msg == "request" for rec in caplog.records)


def test_kv_response_logging(client, monkeypatch, caplog):
    import logging
    caplog.set_level(logging.INFO)
    # Reuse the KV mock from auth_and_kv tests
    import tests.test_auth_and_kv as helper
    mock_client = helper.make_kv_mock()
    import vault_mcp.routes.kv as kv_route
    monkeypatch.setattr(kv_route, "client_for_principal", lambda p: mock_client)

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}
    r = client.put("/secrets/configs/logdemo", headers=h, json={"data": {"a": 1}})
    assert r.status_code == 200
    # Expect a kv_put response log
    assert any(rec.name == "vault_mcp.response" and rec.msg == "kv_put" for rec in caplog.records)


def test_mcp_logging(client, monkeypatch, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    # Initialize
    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 200
    # Expect mcp_result log for initialize
    assert any(rec.name == "vault_mcp.response" and rec.msg == "mcp_result" and getattr(rec, "extra", {}).get("method") == "initialize" for rec in caplog.records)

    # tools/call kv.list (stub list)
    import vault_mcp.mcp_rpc as m
    monkeypatch.setattr(m, "kv_list_v2", lambda c, p: [])
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "kv.list", "arguments": {"prefix": ""}}})
    assert r.status_code == 200
    assert any(rec.name == "vault_mcp.response" and rec.msg == "mcp_result" and getattr(rec, "extra", {}).get("method") == "tools/call" for rec in caplog.records)


def test_stdio_logging(tmp_path):
    # Run the stdio process and ensure it writes a stdio log line
    env = os.environ.copy()
    env.setdefault("SUBJECT", "agent_api")
    env.setdefault("LOG_LEVEL", "DEBUG")
    # Ensure logs dir exists
    os.makedirs("logs", exist_ok=True)
    proc = subprocess.Popen([sys.executable, "scripts/mcp_stdio.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}) + "\n")
        proc.stdin.flush()
        # Allow the process to handle input and write logs, then collect output
        out = ""
        try:
            out, _ = proc.communicate(timeout=1.0)
        except Exception:
            # Fallback: brief sleep and terminate
            time.sleep(0.5)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    # Verify stdio.log contains stdio_request or stdio_result; if the file isn't created yet,
    # fall back to checking the combined stdout/stderr output from the process.
    stdio_log = os.path.join("logs", "stdio.log")
    if os.path.exists(stdio_log):
        with open(stdio_log, "r", encoding="utf-8") as f:
            content = f.read()
        assert "stdio_request" in content or "stdio_result" in content
    else:
        # CI fallback: assert log markers appear in process output
        assert "stdio_request" in out or "stdio_result" in out

import json


def _find_changed_event(evts):
    for e in evts:
        if isinstance(e, dict) and e.get("type") == "resource.changed":
            return e
    return None


def test_sse_emits_resource_changed_on_kv_write(client, monkeypatch):
    import vault_mcp.mcp_rpc as m

    # Avoid touching Vault
    monkeypatch.setattr(m, "client_for_principal", lambda p: object())
    monkeypatch.setattr(m, "kv_write", lambda c, p, d: None)

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    # Trigger a write via MCP
    r = client.post(
        "/mcp/rpc",
        headers=h,
        json={
            "jsonrpc": "2.0",
            "id": "w1",
            "method": "tools/call",
            "params": {"name": "kv.write", "arguments": {"path": "configs/demo", "data": {"foo": "bar"}}},
        },
    )
    assert r.status_code == 200

    # Read recent events via HTTP (deterministic test)
    r = client.get("/mcp/events", params={"type": "resource.changed"})
    assert r.status_code == 200
    evt = _find_changed_event(r.json().get("events", []))
    assert evt and evt.get("uri", "").startswith("kv://agent_api/configs/demo")

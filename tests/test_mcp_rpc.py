def test_mcp_initialize_and_tools_and_kv_calls(client, monkeypatch):
    # Patch kv_read/kv_write used by MCP to an in-memory store
    store = {}

    def _kv_write(_client, path, data):
        cur = store.get(path, {"version": 0})
        store[path] = {"data": data, "version": cur["version"] + 1}

    def _kv_read(_client, path, version=None):
        if path not in store:
            import hvac
            raise hvac.exceptions.InvalidPath("not found")
        v = store[path]["version"]
        return {"data": {"data": store[path]["data"], "metadata": {"version": v}}}

    import vault_mcp.mcp_rpc as mcp
    monkeypatch.setattr(mcp, "kv_write", _kv_write)
    monkeypatch.setattr(mcp, "kv_read", _kv_read)
    # client_for_principal is unused by our stubs but patch to a dummy
    monkeypatch.setattr(mcp, "client_for_principal", lambda p: object())

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    # initialize
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 200
    assert r.json()["result"]["protocolVersion"] == mcp.MCP_PROTOCOL_VERSION

    # tools/list
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r.status_code == 200
    tools = [t["name"] for t in r.json()["result"]["tools"]]
    assert "kv.read" in tools and "kv.write" in tools

    # tools/call -> kv.write
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
    assert r.json()["result"]["content"]["ok"] is True

    # tools/call -> kv.read
    r = client.post(
        "/mcp/rpc",
        headers=h,
        json={
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "tools/call",
            "params": {"name": "kv.read", "arguments": {"path": "configs/demo"}},
        },
    )
    assert r.status_code == 200
    body = r.json()["result"]["content"]
    assert body["data"]["foo"] == "bar"


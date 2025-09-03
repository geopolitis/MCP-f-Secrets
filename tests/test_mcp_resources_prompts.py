def test_resources_list_and_get(client, monkeypatch):
    # Stub kv list/read
    store = {"configs/demo": {"data": {"foo": "bar"}, "version": 1}}
    def _kv_list(_c, path):
        # Accept either bare relative ("configs") or prefixed path ("mcp/agent_api/configs")
        rel = path.split("/", 2)[-1] if "/" in path else path
        prefix = rel + "/"
        return [k[len(prefix):] for k in store.keys() if k.startswith(prefix)]
    def _kv_read(_c, path, version=None):
        key = path.split("/", 2)[-1]
        item = store.get(key)
        if not item:
            return {"data": {"data": {}, "metadata": {"version": 0}}}
        return {"data": {"data": item["data"], "metadata": {"version": item["version"]}}}

    import vault_mcp.mcp_rpc as m
    monkeypatch.setattr(m, "kv_list_v2", _kv_list)
    monkeypatch.setattr(m, "kv_read", _kv_read)
    # Avoid real Vault
    monkeypatch.setattr(m, "client_for_principal", lambda p: object())

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    # resources/list
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "resources/list"})
    assert r.status_code == 200
    uris = [res["uri"] for res in r.json()["result"]["resources"]]
    assert any(u.startswith("kv://agent_api/") for u in uris)

    # resources/get (list under prefix)
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "resources/get", "params": {"uri": "kv://agent_api/configs/"}})
    assert r.status_code == 200
    keys = r.json()["result"]["content"]["keys"]
    assert "demo" in keys

    # resources/get (read exact path)
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 3, "method": "resources/get", "params": {"uri": "kv://agent_api/configs/demo"}})
    assert r.status_code == 200
    data = r.json()["result"]["content"]["data"]
    assert data["foo"] == "bar"


def test_prompts_list_and_get(client):
    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}
    # prompts/list
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 4, "method": "prompts/list"})
    assert r.status_code == 200
    names = [p["name"] for p in r.json()["result"]["prompts"]]
    assert "kv_read" in names and "kv_write" in names

    # prompts/get (kv_read)
    r = client.post("/mcp/rpc", headers=h, json={"jsonrpc": "2.0", "id": 5, "method": "prompts/get", "params": {"name": "kv_read", "arguments": {"path": "configs/demo", "version": 1}}})
    assert r.status_code == 200
    body = r.json()["result"]
    assert body["suggested_tool"]["name"] == "kv.read"

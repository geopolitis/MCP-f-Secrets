from moto import mock_aws


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


@mock_aws
def test_mcp_kms_encrypt_decrypt_tool(client, monkeypatch):
    import base64
    import boto3
    from vault_mcp import aws_kms, settings as settings_module

    # Ensure client_for_principal doesn't hit Vault
    import vault_mcp.mcp_rpc as mcp
    monkeypatch.setattr(mcp, "client_for_principal", lambda p: object())

    region = settings_module.settings.AWS_REGION or "us-east-1"
    kms = boto3.client("kms", region_name=region)
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]

    previous_default = settings_module.settings.AWS_KMS_DEFAULT_KEY_ID
    settings_module.settings.AWS_KMS_DEFAULT_KEY_ID = key_id
    aws_kms.reset_kms_client_cache()

    headers = {"X-API-Key": "dev-key", "Content-Type": "application/json"}
    plaintext = base64.b64encode(b"mcp-kms").decode()

    enc_resp = client.post(
        "/mcp/rpc",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "kms-enc",
            "method": "tools/call",
            "params": {"name": "kms.encrypt", "arguments": {"plaintext": plaintext, "aws": {"region": region}}},
        },
    )
    assert enc_resp.status_code == 200
    ciphertext = enc_resp.json()["result"]["content"]["ciphertext"]

    dec_resp = client.post(
        "/mcp/rpc",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "kms-dec",
            "method": "tools/call",
            "params": {"name": "kms.decrypt", "arguments": {"ciphertext": ciphertext, "aws": {"region": region}}},
        },
    )
    assert dec_resp.status_code == 200
    output = dec_resp.json()["result"]["content"]["plaintext"]
    assert base64.b64decode(output) == b"mcp-kms"

    settings_module.settings.AWS_KMS_DEFAULT_KEY_ID = previous_default
    aws_kms.reset_kms_client_cache()

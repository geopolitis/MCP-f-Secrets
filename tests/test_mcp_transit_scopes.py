def test_mcp_transit_encrypt_decrypt_and_scope(client, monkeypatch):
    # Stub a minimal transit client
    class _Transit:
        def encrypt_data(self, name, plaintext):
            return {"data": {"ciphertext": f"ct:{name}:{plaintext}"}}
        def decrypt_data(self, name, ciphertext):
            return {"data": {"plaintext": f"pt:{name}:{ciphertext}"}}
    class _Secrets:
        transit = _Transit()
    class C:
        secrets = _Secrets()

    import vault_mcp.mcp_rpc as m
    monkeypatch.setattr(m, "client_for_principal", lambda p: C())

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    # encrypt requires write (API key grants all scopes)
    r = client.post(
        "/mcp/rpc",
        headers=h,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "transit.encrypt", "arguments": {"key": "k1", "plaintext": "YWJj"}}},
    )
    assert r.status_code == 200
    assert r.json()["result"]["content"]["ciphertext"].startswith("ct:k1:")

    # decrypt requires read
    r = client.post(
        "/mcp/rpc",
        headers=h,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "transit.decrypt", "arguments": {"key": "k1", "ciphertext": "ct"}}},
    )
    assert r.status_code == 200
    assert r.json()["result"]["content"]["plaintext"].startswith("pt:k1:")

def test_mcp_scope_forbidden(client, monkeypatch):
    # Force principal to have only 'read' scope via JWT; simulate by patching get_principal? Simpler: call a write tool with JWT header
    from jose import jwt
    from vault_mcp.settings import settings
    import vault_mcp.mcp_rpc as m

    # Stub client to avoid real Vault
    class _Secrets: pass
    class C: secrets = _Secrets()
    monkeypatch.setattr(m, "client_for_principal", lambda p: C())

    settings.AUTH_JWT_ENABLED = True
    settings.JWT_HS256_SECRET = "dev-secret"
    settings.JWT_ISSUER = "mcp-auth"
    settings.JWT_AUDIENCE = "mcp-agents"
    tok = jwt.encode({"sub": "only_read", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "scopes": ["read"]}, settings.JWT_HS256_SECRET, algorithm="HS256")
    h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    # Attempt a write-only tool should yield error
    r = client.post(
        "/mcp/rpc",
        headers=h,
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "kv.write", "arguments": {"path": "p", "data": {}}}},
    )
    assert r.status_code == 200
    err = r.json().get("error")
    # In our dispatcher, scope failure returns error with code -32603 and Forbidden message
    assert err and err.get("code") == -32603


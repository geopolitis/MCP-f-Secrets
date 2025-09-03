def test_forbidden_maps_to_403(client, monkeypatch):
    import hvac
    import vault_mcp.routes.kv as kv_route

    # Force kv_read to raise Forbidden
    def forbidden(*args, **kwargs):
        raise hvac.exceptions.Forbidden("nope")
    monkeypatch.setattr(kv_route, "kv_read", forbidden)
    # Avoid real Vault client instantiation
    monkeypatch.setattr(kv_route, "client_for_principal", lambda p: object())
    # Any secret path; auth via API key
    r = client.get("/secrets/configs/demo", headers={"X-API-Key": "dev-key"})
    assert r.status_code == 403
    assert r.json().get("error") == "forbidden"

def test_vault_error_maps_to_502(client, monkeypatch):
    import hvac
    import vault_mcp.routes.transit as t
    def boom(*args, **kwargs):
        raise hvac.exceptions.VaultError("downstream")

    # Monkeypatch the client to have transit methods raising VaultError
    class _Transit:
        def encrypt_data(self, name, plaintext):
            raise hvac.exceptions.VaultError("x")
    class _Secrets:
        transit = _Transit()
    class C:
        secrets = _Secrets()
    monkeypatch.setattr(t, "client_for_principal", lambda p: C())
    r = client.post("/transit/encrypt", headers={"X-API-Key": "dev-key", "Content-Type": "application/json"}, json={"key": "k", "plaintext": ""})
    assert r.status_code == 502
    assert r.json().get("error") == "vault_error"

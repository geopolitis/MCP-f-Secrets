import types


def test_readyz_authenticated(client, monkeypatch):
    # Mock Vault client with is_authenticated True
    c = types.SimpleNamespace(is_authenticated=lambda: True)
    import vault_mcp.routes.health as health
    monkeypatch.setattr(health, "new_vault_client", lambda: c)
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json().get("ok") is True
    assert r.json().get("vault") == "ready"


def test_readyz_unauthenticated(client, monkeypatch):
    c = types.SimpleNamespace(is_authenticated=lambda: False)
    import vault_mcp.routes.health as health
    monkeypatch.setattr(health, "new_vault_client", lambda: c)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json().get("ok") is False
    assert r.json().get("vault") == "unauthenticated"


def test_readyz_vault_error(client, monkeypatch):
    import hvac
    import vault_mcp.routes.health as health
    def boom():
        raise hvac.exceptions.VaultError("fail")
    monkeypatch.setattr(health, "new_vault_client", boom)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json().get("ok") is False
    assert r.json().get("vault") == "error"


def test_readyz_generic_error(client, monkeypatch):
    import vault_mcp.routes.health as health
    monkeypatch.setattr(health, "new_vault_client", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json().get("ok") is False


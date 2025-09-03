from typing import Dict
def make_kv_mock():
    store: Dict[str, Dict] = {}

    class KV2:
        def create_or_update_secret(self, mount_point, path, secret, cas=None):
            store[path] = {"data": secret, "version": store.get(path, {}).get("version", 0) + 1}
            return {"data": {}}

        def read_secret_version(self, mount_point, path, version=None):
            if path not in store:
                import hvac
                raise hvac.exceptions.InvalidPath("not found")
            data = store[path]["data"]
            return {"data": {"data": data, "metadata": {"version": store[path]["version"], "created_time": "now"}}}

        def delete_latest_version_of_secret(self, mount_point, path):
            store.pop(path, None)

        def list_secrets(self, mount_point, path):
            # Return keys relative to provided path (KV v2 semantics)
            prefix = path + "/"
            keys = [k[len(prefix):] for k in store.keys() if k.startswith(prefix)]
            return {"data": {"keys": keys}}

        def undelete_secret_versions(self, mount_point, path, versions):
            return {"data": {}}

        def destroy_secret_versions(self, mount_point, path, versions):
            return {"data": {}}

    class KV:
        v2 = KV2()

    class Secrets:
        kv = KV()

    class Client:
        secrets = Secrets()
    return Client()

def test_kv_list_and_version_ops(client, monkeypatch):
    import vault_mcp.routes.kv as kv_route
    mock_client = make_kv_mock()
    monkeypatch.setattr(kv_route, "client_for_principal", lambda p: mock_client)

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}
    # Create two secrets under configs/
    client.put("/secrets/configs/a", json={"data": {"x": 1}}, headers=h)
    client.put("/secrets/configs/b", json={"data": {"y": 2}}, headers=h)

    # List under prefix configs
    r = client.get("/secrets", params={"prefix": "configs"}, headers={"X-API-Key": "dev-key"})
    assert r.status_code == 200
    ks = r.json().get("keys", [])
    assert "a" in ks and "b" in ks

    # Undelete/destroy version ops should succeed with mock
    r = client.post("/secrets/configs/a:undelete", json={"versions": [1]}, headers=h)
    assert r.status_code == 200 and r.json().get("ok") is True
    r = client.post("/secrets/configs/a:destroy", json={"versions": [1]}, headers=h)
    assert r.status_code == 200 and r.json().get("ok") is True
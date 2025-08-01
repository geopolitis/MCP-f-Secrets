import base64
import types

def make_kv_mock():
    store = {}

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
            keys = [k.split("/", 1)[1] for k in store.keys() if k.startswith(path + "/")]
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

def test_whoami_apikey(client):
    r = client.get("/whoami", headers={"X-API-Key": "dev-key"})
    assert r.status_code == 200
    assert r.json()["subject"] == "agent_api"

def test_kv_put_get_delete(client, monkeypatch):
    # Monkeypatch the vault client for principal
    # Patch the symbol that the router actually imported
    import vault_mcp.routes.kv as kv_route
    mock_client = make_kv_mock()
    monkeypatch.setattr(kv_route, "client_for_principal", lambda p: mock_client)

    h = {"X-API-Key": "dev-key"}
    # PUT
    r = client.put("/secrets/configs/demo", json={"data": {"foo": "bar"}}, headers=h)
    assert r.status_code == 200
    assert r.json()["data"]["foo"] == "bar"
    # GET
    r = client.get("/secrets/configs/demo", headers=h)
    assert r.status_code == 200
    assert r.json()["data"]["foo"] == "bar"
    # DELETE
    r = client.delete("/secrets/configs/demo", headers=h)
    assert r.status_code == 204
    # GET now -> 404
    r = client.get("/secrets/configs/demo", headers=h)
    assert r.status_code == 404
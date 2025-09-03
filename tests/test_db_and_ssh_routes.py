class _DB:
    def generate_credentials(self, name):
        return {
            "data": {"username": f"u_{name}", "password": "p"},
            "lease_id": f"lease-{name}",
            "lease_duration": 60,
            "renewable": True,
        }
class _SSH:
    def generate_credential(self, name, username, ip, port=None):
        return {"data": {"ip": ip, "username": username, "port": port or 22, "key": "otp123"}, "lease_id": "l1", "lease_duration": 30}

    def sign_key(self, name, public_key, cert_type="user", valid_principals=None, ttl=None):
        return {"data": {"signed_key": f"cert:{name}:{cert_type}"}}
class _Secrets:
    database = _DB()
    ssh = _SSH()
class Client:
    secrets = _Secrets()
    class sys:
        @staticmethod
        def renew_lease(lease_id, increment=None):
            return {"lease_duration": 120}

        @staticmethod
        def revoke(lease_id):
            return {}

        @staticmethod
        def revoke_lease(lease_id):  # for compatibility
            return {}
def test_db_and_ssh_endpoints(client, monkeypatch):
    import vault_mcp.routes.db as db_route
    import vault_mcp.routes.ssh as ssh_route

    monkeypatch.setattr(db_route, "client_for_principal", lambda p: Client())
    monkeypatch.setattr(ssh_route, "client_for_principal", lambda p: Client())

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    r = client.post("/db/creds/ro", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["username"].startswith("u_ro") and body["lease_id"].startswith("lease-")
    r = client.post("/db/renew", headers=h, json={"lease_id": "lease-ro"})
    assert r.status_code == 200 and r.json()["ok"] is True
    r = client.post("/db/revoke", headers=h, json={"lease_id": "lease-ro"})
    assert r.status_code == 200 and r.json()["ok"] is True
    r = client.post("/ssh/otp", headers=h, json={"role": "otp", "username": "alice", "ip": "1.2.3.4"})
    assert r.status_code == 200 and r.json()["otp"] == "otp123"
    r = client.post("/ssh/sign", headers=h, json={"role": "ca", "public_key": "ssh-ed25519 AAA...", "cert_type": "user"})
    assert r.status_code == 200 and r.json()["certificate"].startswith("cert:ca:")
class _Transit:
    def encrypt_data(self, name, plaintext):
        return {"data": {"ciphertext": f"vault:v1:{name}:{plaintext}"}}

    def decrypt_data(self, name, ciphertext):
        return {"data": {"plaintext": f"dec:{name}:{ciphertext}"}}

    def sign_data(self, name, input, hash_algorithm=None, signature_algorithm=None):
        return {"data": {"signature": f"sig:{name}:{input}:{hash_algorithm or ''}:{signature_algorithm or ''}"}}

    def verify_signed_data(self, name, input, signature, hash_algorithm=None):
        valid = signature.startswith("sig:") and name in signature and input in signature
        return {"data": {"valid": bool(valid)}}

    def rewrap_data(self, name, ciphertext):
        return {"data": {"ciphertext": f"rewrapped:{name}:{ciphertext}"}}
class _Secrets:
    transit = _Transit()
class TransitMock:
    secrets = _Secrets()
def test_transit_encrypt_decrypt_sign_verify_rewrap(client, monkeypatch):
    import vault_mcp.routes.transit as t
    monkeypatch.setattr(t, "client_for_principal", lambda p: TransitMock())

    h = {"X-API-Key": "dev-key", "Content-Type": "application/json"}

    r = client.post("/transit/encrypt", headers=h, json={"key": "k1", "plaintext": "aGk="})
    assert r.status_code == 200 and r.json()["ciphertext"].startswith("vault:v1:k1:")

    ct = r.json()["ciphertext"]
    r = client.post("/transit/decrypt", headers=h, json={"key": "k1", "ciphertext": ct})
    assert r.status_code == 200 and r.json()["plaintext"].startswith("dec:k1:")

    r = client.post("/transit/sign", headers=h, json={"key": "k1", "input": "YWJj", "hash_algorithm": "sha2-256"})
    sig = r.json()["signature"]
    assert r.status_code == 200 and sig.startswith("sig:k1:")

    r = client.post("/transit/verify", headers=h, json={"key": "k1", "input": "YWJj", "signature": sig})
    assert r.status_code == 200 and r.json()["valid"] is True

    r = client.post("/transit/rewrap", headers=h, json={"key": "k1", "ciphertext": ct})
    assert r.status_code == 200 and r.json()["ciphertext"].startswith("rewrapped:k1:")
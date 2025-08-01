import base64

class _Transit:
    @staticmethod
    def generate_random_bytes(n_bytes: int):
        # Deterministic for test: return n_bytes of 0x01, base64-encoded
        b = b"\x01" * n_bytes
        return {"data": {"random_bytes": base64.b64encode(b).decode("ascii")}}

class _Secrets:
    transit = _Transit()
class TransitMock:
    secrets = _Secrets()

def test_transit_random_hex(client, monkeypatch):
    import vault_mcp.routes.transit as transit_route
    monkeypatch.setattr(transit_route, "client_for_principal", lambda p: TransitMock())

    r = client.get("/transit/random", headers={"X-API-Key": "dev-key"}, params={"bytes": 4, "format": "hex"})
    assert r.status_code == 200
    assert r.json()["random"] == "01010101"

def test_transit_random_base64(client, monkeypatch):
    import vault_mcp.routes.transit as transit_route
    monkeypatch.setattr(transit_route, "client_for_principal", lambda p: TransitMock())

    r = client.get("/transit/random", headers={"X-API-Key": "dev-key"}, params={"bytes": 3})
    assert r.status_code == 200
    # base64 of 0x01 * 3
    assert r.json()["random"] == base64.b64encode(b"\x01\x01\x01").decode("ascii")
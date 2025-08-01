def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json().get("ok") is True

def test_livez(client):
    r = client.get("/livez")
    assert r.status_code == 200
    assert r.json().get("ok") is True
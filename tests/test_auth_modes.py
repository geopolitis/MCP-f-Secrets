from jose import jwt
def test_whoami_jwt_hs256(client, monkeypatch):
    # Adjust runtime settings for JWT HS256
    from vault_mcp.settings import settings
    settings.AUTH_JWT_ENABLED = True
    settings.JWT_HS256_SECRET = "dev-secret"
    settings.JWT_ISSUER = "mcp-auth"
    settings.JWT_AUDIENCE = "mcp-agents"

    token = jwt.encode({"sub": "agent_jwt", "scopes": ["read", "write", "delete", "list"], "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE}, settings.JWT_HS256_SECRET, algorithm="HS256")
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json().get("subject") == "agent_jwt"
def test_whoami_jwt_bad_aud_is_unauthorized(client, monkeypatch):
    from vault_mcp.settings import settings
    settings.AUTH_JWT_ENABLED = True
    settings.JWT_HS256_SECRET = "dev-secret"
    settings.JWT_ISSUER = "mcp-auth"
    settings.JWT_AUDIENCE = "mcp-agents"

    bad = jwt.encode({"sub": "agent_jwt", "iss": settings.JWT_ISSUER, "aud": "wrong"}, settings.JWT_HS256_SECRET, algorithm="HS256")
    r = client.get("/whoami", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401
def test_whoami_mtls_success_and_fail(client):
    from vault_mcp.settings import settings
    settings.AUTH_MTLS_ENABLED = True

    # Success
    r = client.get("/whoami", headers={"X-SSL-Client-S-DN": "CN=agent_mtls,OU=dev", "X-SSL-Client-Verify": "SUCCESS"})
    assert r.status_code == 200
    assert r.json().get("subject") == "agent_mtls"

    # Fail (verify header not success)
    r = client.get("/whoami", headers={"X-SSL-Client-S-DN": "CN=agent_mtls,OU=dev", "X-SSL-Client-Verify": "FAIL"})
    assert r.status_code == 401
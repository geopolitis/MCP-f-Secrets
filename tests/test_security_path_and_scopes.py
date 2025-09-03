from jose import jwt
def test_kv_safe_path_sanitization():
    from vault_mcp.security import kv_safe_path
    prefix = "mcp/agent_api"
    assert kv_safe_path(prefix, "../secrets/../../x") == "mcp/agent_api/x"
    assert kv_safe_path(prefix, "/a//b///c") == "mcp/agent_api/a/b/c"
    assert kv_safe_path(prefix, "") == prefix
def test_missing_scope_forbidden(client):
    # Create a JWT with only 'read' scope and call a 'write' endpoint
    from vault_mcp.settings import settings
    settings.AUTH_JWT_ENABLED = True
    settings.JWT_HS256_SECRET = "dev-secret"
    settings.JWT_ISSUER = "mcp-auth"
    settings.JWT_AUDIENCE = "mcp-agents"
    token = jwt.encode({"sub": "scopes_tester", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "scopes": ["read"]}, settings.JWT_HS256_SECRET, algorithm="HS256")

    # transit/encrypt requires 'write'
    r = client.post("/transit/encrypt", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json={"key": "k1", "plaintext": ""})
    assert r.status_code == 403
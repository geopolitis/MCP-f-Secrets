def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"http_requests_total" in r.content

def test_rate_limit_429(client, monkeypatch):
    from vault_mcp.settings import settings
    from jose import jwt
    # Keep originals to restore
    orig_enabled = settings.RATE_LIMIT_ENABLED
    orig_limit = settings.RATE_LIMIT_REQUESTS
    orig_win = settings.RATE_LIMIT_WINDOW_SECONDS
    orig_jwt_enabled = settings.AUTH_JWT_ENABLED
    orig_secret = settings.JWT_HS256_SECRET
    orig_iss = settings.JWT_ISSUER
    orig_aud = settings.JWT_AUDIENCE
    try:
        # Configure JWT auth for a unique subject to avoid prior rate counts
        settings.AUTH_JWT_ENABLED = True
        settings.JWT_HS256_SECRET = "dev-secret"
        settings.JWT_ISSUER = "mcp-auth"
        settings.JWT_AUDIENCE = "mcp-agents"
        tok = jwt.encode({
            "sub": "rate_test",
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "scopes": ["read", "write", "delete", "list"],
        }, settings.JWT_HS256_SECRET, algorithm="HS256")
        h = {"Authorization": f"Bearer {tok}"}

        # Use a rate-limited endpoint (requires require_scopes): /transit/random
        # Monkeypatch transit client to avoid needing Vault
        import vault_mcp.routes.transit as transit_route
        class _Transit:
            @staticmethod
            def generate_random_bytes(n_bytes: int):
                import base64
                b = b"\x00" * n_bytes
                return {"data": {"random_bytes": base64.b64encode(b).decode("ascii")}}
        class _Secrets:
            transit = _Transit()
        class TransitMock:
            secrets = _Secrets()
        monkeypatch.setattr(transit_route, "client_for_principal", lambda p: TransitMock())

        settings.RATE_LIMIT_ENABLED = True
        settings.RATE_LIMIT_REQUESTS = 2
        settings.RATE_LIMIT_WINDOW_SECONDS = 60
        # First two requests OK
        assert client.get("/transit/random", headers=h).status_code == 200
        assert client.get("/transit/random", headers=h).status_code == 200
        # Third should hit 429
        assert client.get("/transit/random", headers=h).status_code == 429
    finally:
        settings.RATE_LIMIT_ENABLED = orig_enabled
        settings.RATE_LIMIT_REQUESTS = orig_limit
        settings.RATE_LIMIT_WINDOW_SECONDS = orig_win
        settings.AUTH_JWT_ENABLED = orig_jwt_enabled
        settings.JWT_HS256_SECRET = orig_secret
        settings.JWT_ISSUER = orig_iss
        settings.JWT_AUDIENCE = orig_aud
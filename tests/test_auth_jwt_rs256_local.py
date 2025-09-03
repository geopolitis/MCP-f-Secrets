import base64
from jose import jwt
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
def test_whoami_jwt_rs256(client, monkeypatch):
    # Generate an RSA keypair
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key()
    nums = pub.public_numbers()
    n = _b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"))
    e = _b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "t1", "n": n, "e": e}]}

    # Make jwt_auth use our JWKS
    import vault_mcp.auth.jwt_auth as ja
    monkeypatch.setattr(ja, "_get_jwks", lambda: jwks)

    # Configure settings for JWT
    from vault_mcp.settings import settings
    settings.AUTH_JWT_ENABLED = True
    settings.JWT_ISSUER = "mcp-auth"
    settings.JWT_AUDIENCE = "mcp-agents"

    token = jwt.encode(
        {"sub": "agent_jwt", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "scopes": ["read", "write", "delete", "list"]},
        priv_pem,
        algorithm="RS256",
        headers={"kid": "t1"},
    )
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json().get("subject") == "agent_jwt"
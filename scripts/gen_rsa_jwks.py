#!/usr/bin/env python3
"""
Generate an RSA keypair and JWKS, and optionally emit a signed RS256 JWT.

Examples:
  python scripts/gen_rsa_jwks.py --out jwks --kid demo1
  TOK=$(python scripts/gen_rsa_jwks.py --out jwks --kid demo1 \
        --issuer mcp-auth --audience mcp-agents --sub agent_jwt --scopes read,write,list --emit-token)
"""
import argparse
import base64
import json
from pathlib import Path
from typing import List
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt


def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def gen_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_privkey_pem(priv, path: Path):
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def jwk_from_pub(pub, kid: str) -> dict:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="jwks", help="Output directory for jwks.json and private.pem")
    ap.add_argument("--kid", default="demo", help="Key ID to place in JWKS and JWT header")
    ap.add_argument("--issuer", default="mcp-auth")
    ap.add_argument("--audience", default="mcp-agents")
    ap.add_argument("--sub", default="agent_jwt")
    ap.add_argument("--scopes", default="read,write,delete,list")
    ap.add_argument("--ttl", type=int, default=300)
    ap.add_argument("--emit-token", action="store_true")
    ap.add_argument("--reuse-existing", action="store_true", help="Reuse jwks/private.pem if present")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    jwks_path = outdir / "jwks.json"
    priv_path = outdir / "private.pem"

    if args.reuse_existing and jwks_path.exists() and priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        jwks = json.loads(jwks_path.read_text())
    else:
        priv = gen_keypair()
        pub = priv.public_key()
        jwk = jwk_from_pub(pub, args.kid)
        jwks = {"keys": [jwk]}
        save_privkey_pem(priv, priv_path)
        jwks_path.write_text(json.dumps(jwks, indent=2))

    if args.emit_token:
        now = datetime.now(timezone.utc)
        scopes: List[str] = [s.strip() for s in args.scopes.split(",") if s.strip()]
        claims = {
            "sub": args.sub,
            "scopes": scopes,
            "iss": args.issuer,
            "aud": args.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=args.ttl)).timestamp()),
        }
        # Serialize private key to PEM for jose
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": args.kid})
        print(token)


if __name__ == "__main__":
    main()


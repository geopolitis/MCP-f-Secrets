#!/usr/bin/env python3
"""
Generate a simple HS256 JWT for testing the server's JWT auth.

Usage:
  python scripts/gen_jwt.py \
    --secret dev-secret \
    --issuer mcp-auth \
    --audience mcp-agents \
    --sub agentB \
    --scopes read,write,delete,list \
    [--ttl 300]

Prints the signed JWT to stdout.
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

try:
    from jose import jwt
except Exception as e:
    print("python-jose is required. Install with: pip install 'python-jose[cryptography]'", file=sys.stderr)
    raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", required=True)
    ap.add_argument("--issuer", default="mcp-auth")
    ap.add_argument("--audience", default="mcp-agents")
    ap.add_argument("--sub", required=True)
    ap.add_argument("--scopes", default="read,write,delete,list", help="Comma-separated scopes")
    ap.add_argument("--ttl", type=int, default=300, help="Token TTL seconds (0 to omit exp)")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    claims = {
        "sub": args.sub,
        "scopes": scopes,
        "iss": args.issuer,
        "aud": args.audience,
        "iat": int(now.timestamp()),
    }
    if args.ttl and args.ttl > 0:
        exp = now + timedelta(seconds=args.ttl)
        claims["exp"] = int(exp.timestamp())

    token = jwt.encode(claims, args.secret, algorithm="HS256")
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


#!/usr/bin/env python3
"""Helper CLI to manage FastMCP user metadata and credentials."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "ui") not in sys.path:
    sys.path.append(str(ROOT / "ui"))

try:
    from ui.lib.users import UserRecord, delete_user, generate_api_key, load_users, upsert_user
except Exception as exc:  # pragma: no cover
    print(f"Failed to import user helpers: {exc}", file=sys.stderr)
    sys.exit(1)


def run(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Manage FastMCP subjects and credentials")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a new user entry and generate credentials")
    create.add_argument("subject")
    create.add_argument("--scopes", default="read,write,delete,list")
    create.add_argument("--description", default="")
    create.add_argument("--with-jwt", action="store_true", help="Generate a JWT using scripts/gen_jwt.py")
    create.add_argument("--jwt-ttl", type=int, default=900)

    delete_cmd = sub.add_parser("delete", help="Remove a user entry")
    delete_cmd.add_argument("subject")

    sub.add_parser("list", help="List known users")

    args = parser.parse_args(argv)

    if args.command == "list":
        users = load_users()
        print(json.dumps([u.to_dict() for u in users], indent=2))
        return 0

    if args.command == "delete":
        delete_user(args.subject)
        print(f"Deleted user {args.subject}")
        return 0

    if args.command == "create":
        scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        if any(u.subject == args.subject for u in load_users()):
            print(f"Subject {args.subject} already exists", file=sys.stderr)
            return 2
        api_key = generate_api_key()
        jwt_token = None
        jwt_created_iso = None
        jwt_expires_iso = None
        if args.with_jwt:
            secret = os.environ.get("JWT_HS256_SECRET")
            if not secret:
                print("JWT_HS256_SECRET not set; skipping token generation", file=sys.stderr)
            else:
                created_ts = datetime.now(timezone.utc)
                cmd = [
                    sys.executable,
                    "scripts/gen_jwt.py",
                    "--secret",
                    secret,
                    "--sub",
                    args.subject,
                    "--scopes",
                    ",".join(scopes),
                ]
                if args.jwt_ttl:
                    cmd.extend(["--ttl", str(args.jwt_ttl)])
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    print("Failed to generate JWT:", res.stderr or res.stdout, file=sys.stderr)
                else:
                    jwt_token = res.stdout.strip()
                    jwt_created_iso = created_ts.isoformat()
                    if args.jwt_ttl:
                        jwt_expires_iso = (created_ts + timedelta(seconds=args.jwt_ttl)).isoformat()
        ttl_value = args.jwt_ttl if args.with_jwt else None
        record = UserRecord(
            subject=args.subject,
            api_key=api_key,
            scopes=scopes or ["read", "write"],
            description=args.description,
            jwt=jwt_token,
            jwt_created_at=jwt_created_iso,
            jwt_expires_at=jwt_expires_iso,
            jwt_ttl_seconds=ttl_value,
        )
        upsert_user(record)
        print(json.dumps(record.to_dict(), indent=2))
        print(
            "\nNext steps:\n"
            f"  python scripts/gen_policy.py --agent {args.subject} --mount ${'{KV_MOUNT:-secret}'} --prefix ${'{DEFAULT_PREFIX:-mcp}'} > policy.hcl\n"
            f"  vault policy write mcp-agent-{args.subject} policy.hcl\n"
            f"  export API_KEYS_JSON='{{"{api_key}":"{args.subject}"}}'\n"
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

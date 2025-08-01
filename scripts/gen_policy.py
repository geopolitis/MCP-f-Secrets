#!/usr/bin/env python3
"""
Generate a Vault KV v2 policy for an MCP agent.

Usage:
  python scripts/gen_policy.py --agent alice [--mount secret] [--prefix mcp]

Prints HCL policy to stdout and the policy name to stderr.
"""
import argparse
import sys


TEMPLATE = """
path "{mount}/data/{prefix}/{agent}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}

path "{mount}/metadata/{prefix}/{agent}/*" {{
  capabilities = ["read", "list"]
}}

path "{mount}/delete/{prefix}/{agent}/*" {{
  capabilities = ["update"]
}}

path "{mount}/undelete/{prefix}/{agent}/*" {{
  capabilities = ["update"]
}}

path "{mount}/destroy/{prefix}/{agent}/*" {{
  capabilities = ["update"]
}}
""".strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True, help="Agent/subject id")
    ap.add_argument("--mount", default="secret", help="KV v2 mount point")
    ap.add_argument("--prefix", default="mcp", help="Base prefix for agent paths")
    ap.add_argument("--policy-prefix", default="mcp-agent-", help="Policy name prefix")
    args = ap.parse_args()

    name = f"{args.policy_prefix}{args.agent}"
    hcl = TEMPLATE.format(mount=args.mount, prefix=args.prefix, agent=args.agent)
    print(hcl)
    print(f"Policy name: {name}", file=sys.stderr)


if __name__ == "__main__":
    main()


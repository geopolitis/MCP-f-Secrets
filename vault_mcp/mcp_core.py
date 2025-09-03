from typing import Any, Dict, Optional, List

# Date-stamped protocol version
MCP_PROTOCOL_VERSION = "2025-06-18"


def _tool_schemas() -> Dict[str, Dict[str, Any]]:
    return {
        # KV
        "kv.read": {
            "description": "Read a secret from KV v2 under the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "version": {"type": "integer"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"data": {"type": "object"}, "version": {"type": "integer"}}, "required": ["data"]},
        },
        "kv.write": {
            "description": "Write a secret to KV v2 under the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "data": {"type": "object"}},
                "required": ["path", "data"],
                "additionalProperties": True,
            },
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.list": {
            "description": "List keys under a prefix relative to the agent prefix.",
            "input_schema": {"type": "object", "properties": {"prefix": {"type": "string"}}, "required": [], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"keys": {"type": "array", "items": {"type": "string"}}}, "required": ["keys"]},
        },
        "kv.delete": {
            "description": "Delete the latest version of a secret.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.undelete": {
            "description": "Undelete specific versions for a path.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "versions": {"type": "array", "items": {"type": "integer"}}}, "required": ["path", "versions"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.destroy": {
            "description": "Permanently destroy versions for a path.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "versions": {"type": "array", "items": {"type": "integer"}}}, "required": ["path", "versions"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        # Transit
        "transit.encrypt": {
            "description": "Encrypt base64 plaintext with Transit.",
            "input_schema": {"type": "object", "properties": {"key": {"type": "string"}, "plaintext": {"type": "string"}}, "required": ["key", "plaintext"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ciphertext": {"type": "string"}}, "required": ["ciphertext"]},
        },
        "transit.decrypt": {
            "description": "Decrypt Transit ciphertext to base64 plaintext.",
            "input_schema": {"type": "object", "properties": {"key": {"type": "string"}, "ciphertext": {"type": "string"}}, "required": ["key", "ciphertext"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"plaintext": {"type": "string"}}, "required": ["plaintext"]},
        },
        "transit.sign": {
            "description": "Sign input with Transit key.",
            "input_schema": {"type": "object", "properties": {"key": {"type": "string"}, "input": {"type": "string"}, "hash_algorithm": {"type": "string"}, "signature_algorithm": {"type": "string"}}, "required": ["key", "input"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"signature": {"type": "string"}}, "required": ["signature"]},
        },
        "transit.verify": {
            "description": "Verify Transit signature.",
            "input_schema": {"type": "object", "properties": {"key": {"type": "string"}, "input": {"type": "string"}, "signature": {"type": "string"}, "hash_algorithm": {"type": "string"}}, "required": ["key", "input", "signature"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"valid": {"type": "boolean"}}, "required": ["valid"]},
        },
        "transit.rewrap": {
            "description": "Rewrap Transit ciphertext.",
            "input_schema": {"type": "object", "properties": {"key": {"type": "string"}, "ciphertext": {"type": "string"}}, "required": ["key", "ciphertext"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ciphertext": {"type": "string"}}, "required": ["ciphertext"]},
        },
        "transit.random": {
            "description": "Generate random bytes via Transit (base64 or hex).",
            "input_schema": {"type": "object", "properties": {"bytes": {"type": "integer"}, "format": {"type": "string", "enum": ["base64", "hex"]}}, "required": [], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"random": {"type": "string"}, "format": {"type": "string"}}, "required": ["random"]},
        },
        # DB
        "db.issue_creds": {
            "description": "Issue dynamic DB credentials for a role.",
            "input_schema": {"type": "object", "properties": {"role": {"type": "string"}}, "required": ["role"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}, "lease_id": {"type": "string"}}, "required": ["username", "password"]},
        },
        "db.renew": {
            "description": "Renew a Vault lease.",
            "input_schema": {"type": "object", "properties": {"lease_id": {"type": "string"}, "increment": {"type": "integer"}}, "required": ["lease_id"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"lease_duration": {"type": "integer"}}, "required": []},
        },
        "db.revoke": {
            "description": "Revoke a Vault lease.",
            "input_schema": {"type": "object", "properties": {"lease_id": {"type": "string"}}, "required": ["lease_id"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        # SSH
        "ssh.otp": {
            "description": "Generate SSH OTP credential.",
            "input_schema": {"type": "object", "properties": {"role": {"type": "string"}, "ip": {"type": "string"}, "username": {"type": "string"}, "port": {"type": "integer"}}, "required": ["role", "ip", "username"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"otp": {"type": "string"}, "username": {"type": "string"}, "ip": {"type": "string"}}, "required": ["otp"]},
        },
        "ssh.sign": {
            "description": "Sign an SSH public key with Vault SSH CA.",
            "input_schema": {"type": "object", "properties": {"role": {"type": "string"}, "public_key": {"type": "string"}, "cert_type": {"type": "string"}, "valid_principals": {"type": "string"}, "ttl": {"type": "string"}}, "required": ["role", "public_key"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"certificate": {"type": "string"}}, "required": ["certificate"]},
        },
    }


def _initialize_result() -> Dict[str, Any]:
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {"name": "vault-mcp", "version": MCP_PROTOCOL_VERSION},
        "capabilities": {
            "resources": True,
            "prompts": True,
            "tools": list(_tool_schemas().keys()),
            "sessions": True,
            "resumable": False,
        },
    }


def _require_scopes(scopes: List[str], needed: List[str]):
    if not set(needed).issubset(set(scopes)):
        raise PermissionError(f"missing scopes: {needed}")


async def _handle_tool_call_async(name: str, args: Dict[str, Any], p) -> Any:
    # Delayed imports to avoid heavy deps when only doing initialize/tools/list
    from .vault import (
        client_for_principal,
        kv_read,
        kv_write,
        kv_list as kv_list_v2,
        kv_delete_latest as kv_delete_latest_v2,
        kv_undelete as kv_undelete_v2,
        kv_destroy as kv_destroy_v2,
    )
    from .security import kv_safe_path

    client = client_for_principal(p)
    if name == "kv.read":
        _require_scopes(p.scopes, ["read"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        ver = args.get("version")
        res = kv_read(client, rel, version=ver)
        d = res.get("data", {})
        return {"data": d.get("data"), "version": (d.get("metadata") or {}).get("version")}
    if name == "kv.write":
        _require_scopes(p.scopes, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        data = args.get("data") or {}
        kv_write(client, rel, data)
        return {"ok": True}
    if name == "kv.list":
        _require_scopes(p.scopes, ["list"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("prefix", ""))
        keys = kv_list_v2(client, rel)
        return {"keys": keys}
    if name == "kv.delete":
        _require_scopes(p.scopes, ["delete"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        kv_delete_latest_v2(client, rel)
        return {"ok": True}
    if name == "kv.undelete":
        _require_scopes(p.scopes, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        kv_undelete_v2(client, rel, args.get("versions") or [])
        return {"ok": True}
    if name == "kv.destroy":
        _require_scopes(p.scopes, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        kv_destroy_v2(client, rel, args.get("versions") or [])
        return {"ok": True}
    # Transit
    if name == "transit.encrypt":
        _require_scopes(p.scopes, ["write"])
        res = client.secrets.transit.encrypt_data(name=args.get("key"), plaintext=args.get("plaintext"))
        return {"ciphertext": res.get("data", {}).get("ciphertext")}
    if name == "transit.decrypt":
        _require_scopes(p.scopes, ["read"])
        res = client.secrets.transit.decrypt_data(name=args.get("key"), ciphertext=args.get("ciphertext"))
        return {"plaintext": res.get("data", {}).get("plaintext")}
    if name == "transit.sign":
        _require_scopes(p.scopes, ["write"])
        res = client.secrets.transit.sign_data(name=args.get("key"), input=args.get("input"), hash_algorithm=args.get("hash_algorithm"), signature_algorithm=args.get("signature_algorithm"))
        return {"signature": res.get("data", {}).get("signature")}
    if name == "transit.verify":
        _require_scopes(p.scopes, ["read"])
        res = client.secrets.transit.verify_signed_data(name=args.get("key"), input=args.get("input"), signature=args.get("signature"), hash_algorithm=args.get("hash_algorithm"))
        return {"valid": bool((res.get("data", {}) or {}).get("valid"))}
    if name == "transit.rewrap":
        _require_scopes(p.scopes, ["write"])
        res = client.secrets.transit.rewrap_data(name=args.get("key"), ciphertext=args.get("ciphertext"))
        return {"ciphertext": res.get("data", {}).get("ciphertext")}
    if name == "transit.random":
        _require_scopes(p.scopes, ["read"])
        n = int(args.get("bytes", 32) or 32)
        fmt = args.get("format") or "base64"
        res = client.secrets.transit.generate_random_bytes(n_bytes=n)
        b64 = res.get("data", {}).get("random_bytes") or res.get("data", {}).get("random")
        out = b64
        if fmt == "hex" and b64:
            import base64
            out = base64.b64decode(b64).hex()
        return {"random": out, "format": fmt}
    # DB
    if name == "db.issue_creds":
        _require_scopes(p.scopes, ["write"])
        res = client.secrets.database.generate_credentials(name=args.get("role"))
        d = res.get("data", {})
        return {"username": d.get("username"), "password": d.get("password"), "lease_id": res.get("lease_id"), "lease_duration": res.get("lease_duration"), "renewable": res.get("renewable")}
    if name == "db.renew":
        _require_scopes(p.scopes, ["write"])
        try:
            res = client.sys.renew_lease(args.get("lease_id"), increment=args.get("increment"))
        except TypeError:
            res = client.sys.renew_lease(args.get("lease_id"))
        return {"lease_duration": (res or {}).get("lease_duration")}
    if name == "db.revoke":
        _require_scopes(p.scopes, ["write"])
        try:
            client.sys.revoke(args.get("lease_id"))
        except TypeError:
            client.sys.revoke_lease(args.get("lease_id"))
        return {"ok": True}
    # SSH
    if name == "ssh.otp":
        _require_scopes(p.scopes, ["write"])
        op = args
        res = client.secrets.ssh.generate_credential(name=op.get("role"), username=op.get("username"), ip=op.get("ip"), port=op.get("port"))
        d = res.get("data", {})
        return {"ip": d.get("ip"), "username": d.get("username"), "port": d.get("port"), "otp": d.get("key") or d.get("otp"), "lease_id": res.get("lease_id"), "lease_duration": res.get("lease_duration")}
    if name == "ssh.sign":
        _require_scopes(p.scopes, ["write"])
        op = args
        res = client.secrets.ssh.sign_key(name=op.get("role"), public_key=op.get("public_key"), cert_type=op.get("cert_type"), valid_principals=op.get("valid_principals"), ttl=op.get("ttl"))
        d = res.get("data", {})
        cert = d.get("signed_key") or d.get("signed_key_pem") or d.get("ssh_signature")
        return {"certificate": cert}
    raise ValueError(f"unknown tool: {name}")


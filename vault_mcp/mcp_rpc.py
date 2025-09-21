import asyncio
import json
import time
from typing import Any, Dict, Optional, List, Tuple, Set
from fastapi import APIRouter, Depends, Request
import logging
from fastapi.responses import StreamingResponse
from .settings import settings
from collections import deque
from .security import get_principal, kv_safe_path
from .models import Principal
from .vault import (
    client_for_principal,
    kv_read,
    kv_write,
    kv_list as kv_list_v2,
    kv_delete_latest as kv_delete_latest_v2,
    kv_undelete as kv_undelete_v2,
    kv_destroy as kv_destroy_v2,
)
from .aws_kms import (
    KMSDisabledError,
    kms_enabled,
    kms_decrypt as aws_kms_decrypt,
    kms_encrypt as aws_kms_encrypt,
    kms_generate_data_key as aws_kms_generate_data_key,
    kms_sign as aws_kms_sign,
    kms_verify as aws_kms_verify,
)

router = APIRouter(prefix="/mcp", tags=["mcp"])

MCP_PROTOCOL_VERSION = "2025-06-18"


def _tool_schemas() -> Dict[str, Dict[str, Any]]:
    tools: Dict[str, Dict[str, Any]] = {
        "kv.read": {
            "description": "Read a secret from KV v2 under the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "version": {"type": "integer"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"data": {"type": "object"}, "version": {"type": "integer"}}, "required": ["data"]},
        },
        "kv.write": {
            "description": "Write a secret to KV v2 under the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "data": {"type": "object"},
                },
                "required": ["path", "data"],
                "additionalProperties": True,
            },
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.list": {
            "description": "List keys under a prefix relative to the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {"prefix": {"type": "string"}},
                "required": [],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"keys": {"type": "array", "items": {"type": "string"}}}, "required": ["keys"]},
        },
        "kv.delete": {
            "description": "Delete the latest version of a secret at path under the agent prefix.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.undelete": {
            "description": "Undelete specific versions for a given path.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "versions": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["path", "versions"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        "kv.destroy": {
            "description": "Permanently destroy specific versions for a given path.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "versions": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["path", "versions"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        },
        # Transit tools
        "transit.encrypt": {
            "description": "Encrypt base64 plaintext with Transit.",
            "input_schema": {
                "type": "object",
                "properties": {"key": {"type": "string"}, "plaintext": {"type": "string"}},
                "required": ["key", "plaintext"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"ciphertext": {"type": "string"}}, "required": ["ciphertext"]},
        },
        "transit.decrypt": {
            "description": "Decrypt Transit ciphertext, returns base64 plaintext.",
            "input_schema": {
                "type": "object",
                "properties": {"key": {"type": "string"}, "ciphertext": {"type": "string"}},
                "required": ["key", "ciphertext"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"plaintext": {"type": "string"}}, "required": ["plaintext"]},
        },
        "transit.sign": {
            "description": "Sign input with Transit key.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "input": {"type": "string"},
                    "hash_algorithm": {"type": "string"},
                    "signature_algorithm": {"type": "string"},
                },
                "required": ["key", "input"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"signature": {"type": "string"}}, "required": ["signature"]},
        },
        "transit.verify": {
            "description": "Verify Transit signature.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "input": {"type": "string"},
                    "signature": {"type": "string"},
                    "hash_algorithm": {"type": "string"},
                },
                "required": ["key", "input", "signature"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"valid": {"type": "boolean"}}, "required": ["valid"]},
        },
        "transit.rewrap": {
            "description": "Rewrap Transit ciphertext.",
            "input_schema": {
                "type": "object",
                "properties": {"key": {"type": "string"}, "ciphertext": {"type": "string"}},
                "required": ["key", "ciphertext"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"ciphertext": {"type": "string"}}, "required": ["ciphertext"]},
        },
        "transit.random": {
            "description": "Generate random bytes via Transit (base64 or hex).",
            "input_schema": {
                "type": "object",
                "properties": {"bytes": {"type": "integer"}, "format": {"type": "string", "enum": ["base64", "hex"]}},
                "required": [],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object", "properties": {"random": {"type": "string"}, "format": {"type": "string"}}, "required": ["random"]},
        },
        # DB tools
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
        # SSH tools
        "ssh.otp": {
            "description": "Generate SSH OTP credential via Vault SSH.",
            "input_schema": {"type": "object", "properties": {"role": {"type": "string"}, "ip": {"type": "string"}, "username": {"type": "string"}, "port": {"type": "integer"}}, "required": ["role", "ip", "username"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"otp": {"type": "string"}, "username": {"type": "string"}, "ip": {"type": "string"}}, "required": ["otp"]},
        },
        "ssh.sign": {
            "description": "Sign an SSH public key with Vault SSH CA.",
            "input_schema": {"type": "object", "properties": {"role": {"type": "string"}, "public_key": {"type": "string"}, "cert_type": {"type": "string"}, "valid_principals": {"type": "string"}, "ttl": {"type": "string"}}, "required": ["role", "public_key"], "additionalProperties": False},
            "output_schema": {"type": "object", "properties": {"certificate": {"type": "string"}}, "required": ["certificate"]},
        },
    }
    aws_schema = {
        "type": "object",
        "properties": {
            "access_key_id": {"type": "string"},
            "secret_access_key": {"type": "string"},
            "session_token": {"type": "string"},
            "region": {"type": "string"},
            "endpoint": {"type": "string"},
        },
        "additionalProperties": False,
    }
    tools.update(
        {
            "kms.encrypt": {
                "description": "Encrypt base64 plaintext with AWS KMS (requires AWS_KMS_ENABLED).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "plaintext": {"type": "string"},
                        "encryption_context": {"type": "object", "additionalProperties": {"type": "string"}},
                        "grant_tokens": {"type": "array", "items": {"type": "string"}},
                        "aws": aws_schema,
                    },
                    "required": ["plaintext"],
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "properties": {"ciphertext": {"type": "string"}}, "required": ["ciphertext"]},
            },
            "kms.decrypt": {
                "description": "Decrypt AWS KMS ciphertext (requires AWS_KMS_ENABLED).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ciphertext": {"type": "string"},
                        "encryption_context": {"type": "object", "additionalProperties": {"type": "string"}},
                        "grant_tokens": {"type": "array", "items": {"type": "string"}},
                        "aws": aws_schema,
                    },
                    "required": ["ciphertext"],
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "properties": {"plaintext": {"type": "string"}}, "required": ["plaintext"]},
            },
            "kms.generate_data_key": {
                "description": "Generate a data key via AWS KMS (requires AWS_KMS_ENABLED).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "key_spec": {"type": "string"},
                        "number_of_bytes": {"type": "integer"},
                        "encryption_context": {"type": "object", "additionalProperties": {"type": "string"}},
                        "grant_tokens": {"type": "array", "items": {"type": "string"}},
                        "aws": aws_schema,
                    },
                    "required": [],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "ciphertext": {"type": "string"},
                        "plaintext": {"type": "string"},
                    },
                    "required": ["ciphertext", "plaintext"],
                },
            },
            "kms.sign": {
                "description": "Sign a message using AWS KMS (requires AWS_KMS_ENABLED).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "message": {"type": "string"},
                        "message_digest": {"type": "string"},
                        "signing_algorithm": {"type": "string"},
                        "message_type": {"type": "string"},
                        "grant_tokens": {"type": "array", "items": {"type": "string"}},
                        "aws": aws_schema,
                    },
                    "required": ["signing_algorithm"],
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "properties": {"signature": {"type": "string"}}, "required": ["signature"]},
            },
            "kms.verify": {
                "description": "Verify a signature with AWS KMS (requires AWS_KMS_ENABLED).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "signature": {"type": "string"},
                        "message": {"type": "string"},
                        "message_digest": {"type": "string"},
                        "signing_algorithm": {"type": "string"},
                        "message_type": {"type": "string"},
                        "grant_tokens": {"type": "array", "items": {"type": "string"}},
                        "aws": aws_schema,
                    },
                    "required": ["signature", "signing_algorithm"],
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "properties": {"valid": {"type": "boolean"}}, "required": ["valid"]},
            },
        }
    )
    return tools


def _jsonrpc_response(id: Any, result: Any = None, error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if error is not None:
        return {"jsonrpc": "2.0", "id": id, "error": error}
    return {"jsonrpc": "2.0", "id": id, "result": result}


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


# Simple SSE broadcaster for tool events
_sse_subscribers: List[asyncio.Queue] = []
_sse_lock = asyncio.Lock()
# Map of per-connection subscriptions to resource URI prefixes
_sse_subscriptions: Dict[asyncio.Queue, Set[str]] = {}
_recent_events: deque = deque(maxlen=200)


async def _broadcast(event: Dict[str, Any]):
    async with _sse_lock:
        try:
            _recent_events.append(event)
        except Exception:
            pass
        for q in list(_sse_subscribers):
            try:
                await q.put(event)
            except Exception:
                pass


async def _broadcast_resource_changed(uri: str, subject: str):
    ev = {"type": "resource.changed", "uri": uri, "subject": subject, "ts": int(time.time())}
    async with _sse_lock:
        try:
            _recent_events.append(ev)
        except Exception:
            pass
        for q in list(_sse_subscribers):
            try:
                prefixes = _sse_subscriptions.get(q, set())
                # If no subscription recorded, skip targeted notifications
                if prefixes and not any(uri.startswith(pref) for pref in prefixes):
                    continue
                await q.put(ev)
            except Exception:
                pass


def _require_scopes(p: Principal, needed: List[str]):
    if not set(needed).issubset(set(p.scopes)):
        raise PermissionError(f"missing scopes: {needed}")


async def _handle_tool_call_async(name: str, args: Dict[str, Any], p: Principal) -> Any:
    client = client_for_principal(p)
    if name.startswith("kms.") and not kms_enabled():
        raise RuntimeError("AWS KMS support is disabled")
    if name == "kv.read":
        _require_scopes(p, ["read"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        ver = args.get("version")
        res = kv_read(client, rel, version=ver)
        d = res.get("data", {})
        return {"data": d.get("data"), "version": (d.get("metadata") or {}).get("version")}
    if name == "kv.write":
        _require_scopes(p, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        data = args.get("data") or {}
        kv_write(client, rel, data)
        try:
            await _broadcast_resource_changed(f"kv://{p.subject}/" + (args.get("path") or ""), p.subject)
        except Exception:
            pass
        return {"ok": True}
    if name == "kv.list":
        _require_scopes(p, ["list"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("prefix", ""))
        keys = kv_list_v2(client, rel)
        return {"keys": keys}
    if name == "kv.delete":
        _require_scopes(p, ["delete"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        kv_delete_latest_v2(client, rel)
        try:
            await _broadcast_resource_changed(f"kv://{p.subject}/" + (args.get("path") or ""), p.subject)
        except Exception:
            pass
        return {"ok": True}
    if name == "kv.undelete":
        _require_scopes(p, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        versions = args.get("versions") or []
        kv_undelete_v2(client, rel, versions)
        try:
            await _broadcast_resource_changed(f"kv://{p.subject}/" + (args.get("path") or ""), p.subject)
        except Exception:
            pass
        return {"ok": True}
    if name == "kv.destroy":
        _require_scopes(p, ["write"])
        rel = kv_safe_path(p.vault_path_prefix, args.get("path", ""))
        versions = args.get("versions") or []
        kv_destroy_v2(client, rel, versions)
        try:
            await _broadcast_resource_changed(f"kv://{p.subject}/" + (args.get("path") or ""), p.subject)
        except Exception:
            pass
        return {"ok": True}
    # Transit tools
    if name == "transit.encrypt":
        _require_scopes(p, ["write"])
        key = args.get("key"); pt = args.get("plaintext")
        res = client.secrets.transit.encrypt_data(name=key, plaintext=pt)
        return {"ciphertext": res.get("data", {}).get("ciphertext")}
    if name == "transit.decrypt":
        _require_scopes(p, ["read"])
        key = args.get("key"); ct = args.get("ciphertext")
        res = client.secrets.transit.decrypt_data(name=key, ciphertext=ct)
        return {"plaintext": res.get("data", {}).get("plaintext")}
    if name == "transit.sign":
        _require_scopes(p, ["write"])
        res = client.secrets.transit.sign_data(name=args.get("key"), input=args.get("input"), hash_algorithm=args.get("hash_algorithm"), signature_algorithm=args.get("signature_algorithm"))
        return {"signature": res.get("data", {}).get("signature")}
    if name == "transit.verify":
        _require_scopes(p, ["read"])
        res = client.secrets.transit.verify_signed_data(name=args.get("key"), input=args.get("input"), signature=args.get("signature"), hash_algorithm=args.get("hash_algorithm"))
        return {"valid": bool((res.get("data", {}) or {}).get("valid"))}
    if name == "transit.rewrap":
        _require_scopes(p, ["write"])
        res = client.secrets.transit.rewrap_data(name=args.get("key"), ciphertext=args.get("ciphertext"))
        return {"ciphertext": res.get("data", {}).get("ciphertext")}
    if name == "transit.random":
        _require_scopes(p, ["read"])
        n = int(args.get("bytes", 32) or 32)
        fmt = args.get("format") or "base64"
        res = client.secrets.transit.generate_random_bytes(n_bytes=n)
        b64 = res.get("data", {}).get("random_bytes") or res.get("data", {}).get("random")
        out = b64
        if fmt == "hex" and b64:
            import base64
            out = base64.b64decode(b64).hex()
        return {"random": out, "format": fmt}
    if name == "kms.encrypt":
        _require_scopes(p, ["write"])
        creds = args.get("aws") if isinstance(args.get("aws"), dict) else None
        try:
            return {
                "ciphertext": aws_kms_encrypt(
                    key_id=args.get("key_id"),
                    plaintext_b64=args.get("plaintext"),
                    encryption_context=args.get("encryption_context"),
                    grant_tokens=args.get("grant_tokens"),
                    credentials=creds,
                )
            }
        except (KMSDisabledError, ValueError) as exc:
            raise RuntimeError(str(exc))
    if name == "kms.decrypt":
        _require_scopes(p, ["read"])
        creds = args.get("aws") if isinstance(args.get("aws"), dict) else None
        try:
            return {
                "plaintext": aws_kms_decrypt(
                    ciphertext_b64=args.get("ciphertext"),
                    encryption_context=args.get("encryption_context"),
                    grant_tokens=args.get("grant_tokens"),
                    credentials=creds,
                )
            }
        except (KMSDisabledError, ValueError) as exc:
            raise RuntimeError(str(exc))
    if name == "kms.generate_data_key":
        _require_scopes(p, ["write"])
        creds = args.get("aws") if isinstance(args.get("aws"), dict) else None
        try:
            return {
                **aws_kms_generate_data_key(
                    key_id=args.get("key_id"),
                    key_spec=args.get("key_spec"),
                    number_of_bytes=args.get("number_of_bytes"),
                    encryption_context=args.get("encryption_context"),
                    grant_tokens=args.get("grant_tokens"),
                    credentials=creds,
                )
            }
        except (KMSDisabledError, ValueError) as exc:
            raise RuntimeError(str(exc))
    if name == "kms.sign":
        _require_scopes(p, ["write"])
        creds = args.get("aws") if isinstance(args.get("aws"), dict) else None
        try:
            return {
                "signature": aws_kms_sign(
                    key_id=args.get("key_id"),
                    message_b64=args.get("message"),
                    message_digest_b64=args.get("message_digest"),
                    signing_algorithm=args.get("signing_algorithm"),
                    message_type=args.get("message_type"),
                    grant_tokens=args.get("grant_tokens"),
                    credentials=creds,
                )
            }
        except (KMSDisabledError, ValueError) as exc:
            raise RuntimeError(str(exc))
    if name == "kms.verify":
        _require_scopes(p, ["read"])
        creds = args.get("aws") if isinstance(args.get("aws"), dict) else None
        try:
            return {
                "valid": aws_kms_verify(
                    key_id=args.get("key_id"),
                    signature_b64=args.get("signature"),
                    message_b64=args.get("message"),
                    message_digest_b64=args.get("message_digest"),
                    signing_algorithm=args.get("signing_algorithm"),
                    message_type=args.get("message_type"),
                    grant_tokens=args.get("grant_tokens"),
                    credentials=creds,
                )
            }
        except (KMSDisabledError, ValueError) as exc:
            raise RuntimeError(str(exc))
    # DB tools
    if name == "db.issue_creds":
        _require_scopes(p, ["write"])
        role = args.get("role")
        res = client.secrets.database.generate_credentials(name=role)
        d = res.get("data", {})
        return {"username": d.get("username"), "password": d.get("password"), "lease_id": res.get("lease_id"), "lease_duration": res.get("lease_duration"), "renewable": res.get("renewable")}
    if name == "db.renew":
        _require_scopes(p, ["write"])
        inc = args.get("increment")
        try:
            res = client.sys.renew_lease(args.get("lease_id"), increment=inc)
        except TypeError:
            res = client.sys.renew_lease(args.get("lease_id"))
        return {"lease_duration": (res or {}).get("lease_duration")}
    if name == "db.revoke":
        _require_scopes(p, ["write"])
        try:
            client.sys.revoke(args.get("lease_id"))
        except TypeError:
            client.sys.revoke_lease(args.get("lease_id"))
        return {"ok": True}
    # SSH tools
    if name == "ssh.otp":
        _require_scopes(p, ["write"])
        op = args
        res = client.secrets.ssh.generate_credential(name=op.get("role"), username=op.get("username"), ip=op.get("ip"), port=op.get("port"))
        d = res.get("data", {})
        return {"ip": d.get("ip"), "username": d.get("username"), "port": d.get("port"), "otp": d.get("key") or d.get("otp"), "lease_id": res.get("lease_id"), "lease_duration": res.get("lease_duration")}
    if name == "ssh.sign":
        _require_scopes(p, ["write"])
        op = args
        res = client.secrets.ssh.sign_key(name=op.get("role"), public_key=op.get("public_key"), cert_type=op.get("cert_type"), valid_principals=op.get("valid_principals"), ttl=op.get("ttl"))
        d = res.get("data", {})
        cert = d.get("signed_key") or d.get("signed_key_pem") or d.get("ssh_signature")
        return {"certificate": cert}
    raise ValueError(f"unknown tool: {name}")


@router.post("/rpc")
async def mcp_rpc(body: Dict[str, Any], p: Principal = Depends(get_principal)):
    # Minimal JSON-RPC 2.0 dispatcher with structured logs
    j = body or {}
    method = j.get("method"); id_ = j.get("id")
    start = time.time()
    req_logger = logging.getLogger("vault_mcp.request")
    resp_logger = logging.getLogger("vault_mcp.response")
    try:
        req_logger.debug("mcp_rpc", extra={"extra": {"id": id_, "method": method, "subject": p.subject}})
    except Exception:
        pass
    try:
        if j.get("jsonrpc") != "2.0":
            res = _jsonrpc_response(id_, error={"code": -32600, "message": "Invalid Request"})
            try:
                resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "status": "invalid", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
            except Exception:
                pass
            return res
        if method == "initialize":
            res = _jsonrpc_response(id_, _initialize_result())
            try:
                resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "status": "ok", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
            except Exception:
                pass
            return res
        if method == "shutdown":
            res = _jsonrpc_response(id_, {"ok": True})
            try:
                resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "status": "ok", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
            except Exception:
                pass
            return res
        if method == "tools/list":
            return _jsonrpc_response(id_, {"tools": [{"name": k, **v} for k, v in _tool_schemas().items()]})
        if method == "resources/list":
            # Advertise a KV root resource for this subject (no Vault calls)
            res = [{
                "uri": f"kv://{p.subject}/",
                "name": f"{p.subject} KV root",
                "mimeType": "application/json",
                "description": "Agent-scoped KV namespace root",
            }]
            return _jsonrpc_response(id_, {"resources": res})
        if method == "resources/get":
            params = j.get("params") or {}
            uri = params.get("uri") or ""
            content, mt = await _resource_get(uri, p)
            return _jsonrpc_response(id_, {"uri": uri, "mimeType": mt, "content": content})
        if method == "resources/subscribe":
            params = j.get("params") or {}
            prefix = params.get("uriPrefix") or ""
            if not prefix:
                return _jsonrpc_response(id_, error={"code": -32602, "message": "uriPrefix required"})
            async with _sse_lock:
                # Subscriptions are per-SSE connection; here we record desired prefixes
                # The SSE handler initializes the queue entry in _sse_subscriptions.
                for q in _sse_subscribers:
                    _sse_subscriptions.setdefault(q, set())
                    _sse_subscriptions[q].add(prefix)
            return _jsonrpc_response(id_, {"ok": True})
        if method == "resources/unsubscribe":
            params = j.get("params") or {}
            prefix = params.get("uriPrefix")
            async with _sse_lock:
                for q in _sse_subscribers:
                    if q in _sse_subscriptions:
                        if prefix:
                            _sse_subscriptions[q].discard(prefix)
                        else:
                            _sse_subscriptions[q].clear()
            return _jsonrpc_response(id_, {"ok": True})
        if method == "prompts/list":
            prompts = [
                {
                    "name": "kv_read",
                    "description": "Read a KV secret by relative path under agent namespace.",
                    "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "version": {"type": "integer"}}, "required": ["path"]},
                },
                {
                    "name": "kv_write",
                    "description": "Write a KV secret by relative path with JSON body.",
                    "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "data": {"type": "object"}}, "required": ["path", "data"]},
                },
            ]
            return _jsonrpc_response(id_, {"prompts": prompts})
        if method == "prompts/get":
            params = j.get("params") or {}
            name = params.get("name"); arguments = params.get("arguments") or {}
            prompt = await _prompt_get(name, arguments, p)
            return _jsonrpc_response(id_, prompt)
        if method == "tools/call":
            params = j.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                result = await _handle_tool_call_async(name, args, p)
                res = _jsonrpc_response(id_, {"content": result})
                try:
                    resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "tool": name, "status": "ok", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
                except Exception:
                    pass
                return res
            finally:
                try:
                    await _broadcast({"type": "tool.completed", "tool": name, "subject": p.subject, "ts": int(time.time())})
                except Exception:
                    pass
        return _jsonrpc_response(id_, error={"code": -32601, "message": "Method not found"})
    except PermissionError as e:
        res = _jsonrpc_response(id_, error={"code": -32603, "message": f"Forbidden: {e}"})
        try:
            resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "status": "forbidden", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
        except Exception:
            pass
        return res
    except Exception as e:
        res = _jsonrpc_response(id_, error={"code": -32000, "message": str(e)})
        try:
            resp_logger.info("mcp_result", extra={"extra": {"id": id_, "method": method, "status": "error", "duration_ms": int((time.time()-start)*1000), "subject": p.subject}})
        except Exception:
            pass
        return res


@router.get("/sse")
async def mcp_sse():
    queue: asyncio.Queue = asyncio.Queue()
    async with _sse_lock:
        _sse_subscribers.append(queue)
        _sse_subscriptions.setdefault(queue, set())
    try:
        logging.getLogger("vault_mcp.response").debug("mcp_sse_open", extra={"extra": {}})
    except Exception:
        pass

    async def event_stream():
        try:
            # Send an initial hello event so clients don't block on first read
            first = json.dumps({"type": "hello", "ts": int(time.time())})
            yield f"data: {first}\n\n"
            while True:
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=float(settings.SSE_KEEPALIVE_SECONDS))
                    payload = json.dumps(evt)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    payload = json.dumps({"type": "keepalive", "ts": int(time.time())})
                    yield f"data: {payload}\n\n"
        finally:
            async with _sse_lock:
                try:
                    _sse_subscribers.remove(queue)
                except ValueError:
                    pass
                _sse_subscriptions.pop(queue, None)
            try:
                logging.getLogger("vault_mcp.response").debug("mcp_sse_close", extra={"extra": {}})
            except Exception:
                pass

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/events")
async def list_recent_events(type: Optional[str] = None):
    # Expose recent server-emitted events (excluding keepalives/hello) for testing and debugging
    items = list(_recent_events)
    if type:
        items = [e for e in items if isinstance(e, dict) and e.get("type") == type]
    return {"events": items}


def _parse_kv_uri(uri: str) -> Tuple[str, str, Optional[int]]:
    # kv://<subject>/<rel_path>[?version=N]
    if not uri.startswith("kv://"):
        raise ValueError("unsupported URI scheme")
    rest = uri[5:]
    subject, _, tail = rest.partition("/")
    path_part, _, q = tail.partition("?")
    version = None
    if q.startswith("version="):
        try:
            version = int(q.split("=", 1)[1])
        except Exception:
            version = None
    return subject, path_part, version


async def _resource_get(uri: str, p: Principal) -> Tuple[Dict[str, Any], str]:
    if uri.startswith("kv://"):
        subj, rel, ver = _parse_kv_uri(uri)
        if subj != p.subject:
            raise PermissionError("cross-subject access forbidden")
        client = client_for_principal(p)
        if rel.endswith("/") or rel == "":
            # list under prefix
            keys = kv_list_v2(client, kv_safe_path(p.vault_path_prefix, rel.rstrip("/")))
            return {"keys": keys}, "application/json"
        # read secret
        res = kv_read(client, kv_safe_path(p.vault_path_prefix, rel), version=ver)
        d = res.get("data", {})
        return {"data": d.get("data"), "version": (d.get("metadata") or {}).get("version")}, "application/json"
    raise ValueError("unsupported resource URI")


async def _prompt_get(name: str, arguments: Dict[str, Any], p: Principal) -> Dict[str, Any]:
    if name == "kv_read":
        path = arguments.get("path"); version = arguments.get("version")
        return {
            "name": name,
            "messages": [
                {"role": "system", "content": "You are testing kv.read against a Vault-backed MCP server."},
                {"role": "user", "content": f"Read the secret at path '{path}' (version={version})."},
            ],
            "suggested_tool": {"name": "kv.read", "arguments": {"path": path, "version": version}},
        }
    if name == "kv_write":
        path = arguments.get("path"); data = arguments.get("data") or {}
        return {
            "name": name,
            "messages": [
                {"role": "system", "content": "You are testing kv.write against a Vault-backed MCP server."},
                {"role": "user", "content": f"Write JSON data to path '{path}'."},
            ],
            "suggested_tool": {"name": "kv.write", "arguments": {"path": path, "data": data}},
        }
    raise ValueError("unknown prompt")

from typing import Optional
from fastapi import Depends, Query, Request
from .utils import Router as APIRouter
import logging
import hvac
from ..models import SecretWrite, SecretRead, VersionsOp, Principal
from ..security import require_scopes, kv_safe_path
from ..vault import client_for_principal, kv_write, kv_read, kv_delete_latest, kv_list, kv_undelete, kv_destroy

router = APIRouter(prefix="/secrets", tags=["kv"])

@router.put("/{path:path}", response_model=SecretRead)
async def put_secret(path: str, body: SecretWrite, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, path)
    kv_write(client, full_rel, body.data)
    read = kv_read(client, full_rel)
    d = read["data"]
    res = SecretRead(data=d["data"], version=d["metadata"].get("version"), created_time=d["metadata"].get("created_time"))
    try:
        logging.getLogger("vault_mcp.response").info("kv_put", extra={"extra": {"subject": p.subject, "path": full_rel, "keys": list(res.data.keys()), "version": res.version, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return res

@router.get("/{path:path}", response_model=SecretRead)
async def get_secret(path: str, version: Optional[int] = None, request: Request = None, p: Principal = Depends(require_scopes(["read"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, path)
    read = kv_read(client, full_rel, version=version)
    d = read["data"]
    res = SecretRead(data=d["data"], version=d["metadata"].get("version"), created_time=d["metadata"].get("created_time"))
    try:
        logging.getLogger("vault_mcp.response").info("kv_get", extra={"extra": {"subject": p.subject, "path": full_rel, "keys": list(res.data.keys()), "version": res.version, "request_id": request.headers.get("x-request-id") if request else None}})
    except Exception:
        pass
    return res

@router.delete("/{path:path}", status_code=204)
async def delete_secret(path: str, request: Request, p: Principal = Depends(require_scopes(["delete"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, path)
    kv_delete_latest(client, full_rel)
    try:
        logging.getLogger("vault_mcp.response").info("kv_delete", extra={"extra": {"subject": p.subject, "path": full_rel, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return

@router.get("", summary="List keys under a prefix")
async def list_secrets(prefix: str = Query("") , request: Request = None, p: Principal = Depends(require_scopes(["list"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, prefix)
    try:
        keys = kv_list(client, full_rel)
    except hvac.exceptions.InvalidPath:
        keys = []
    try:
        logging.getLogger("vault_mcp.response").info("kv_list", extra={"extra": {"subject": p.subject, "prefix": full_rel, "count": len(keys), "request_id": request.headers.get("x-request-id") if request else None}})
    except Exception:
        pass
    return {"keys": keys}

@router.post("/{path:path}:undelete")
async def undelete_versions(path: str, body: VersionsOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, path)
    kv_undelete(client, full_rel, body.versions)
    try:
        logging.getLogger("vault_mcp.response").info("kv_undelete", extra={"extra": {"subject": p.subject, "path": full_rel, "versions": body.versions, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return {"ok": True}

@router.post("/{path:path}:destroy")
async def destroy_versions(path: str, body: VersionsOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    full_rel = kv_safe_path(p.vault_path_prefix, path)
    kv_destroy(client, full_rel, body.versions)
    try:
        logging.getLogger("vault_mcp.response").info("kv_destroy", extra={"extra": {"subject": p.subject, "path": full_rel, "versions": body.versions, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return {"ok": True}
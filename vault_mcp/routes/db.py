from fastapi import Depends, Request
from .utils import Router as APIRouter
import logging
from ..models import LeaseOp, Principal
from ..security import require_scopes
from ..vault import client_for_principal

router = APIRouter(prefix="/db", tags=["database"])
@router.post("/creds/{role}")
async def issue_db_creds(role: str, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.database.generate_credentials(name=role)
    data = res.get("data", {})
    out = {
        "username": data.get("username"),
        "password": data.get("password"),
        "lease_id": res.get("lease_id"),
        "lease_duration": res.get("lease_duration"),
        "renewable": res.get("renewable"),
    }
    try:
        logging.getLogger("vault_mcp.response").info(
            "db_issue",
            extra={
                "extra": {
                    "subject": p.subject,
                    "role": role,
                    "lease_id_suffix": (out.get("lease_id") or "")[ -8: ],
                    "request_id": request.headers.get("x-request-id"),
                }
            },
        )
    except Exception:
        pass
    return out

@router.post("/renew")
async def renew_lease(body: LeaseOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    try:
        res = client.sys.renew_lease(body.lease_id, increment=body.increment)
    except TypeError:
        res = client.sys.renew_lease(body.lease_id)
    try:
        logging.getLogger("vault_mcp.response").info(
            "db_renew",
            extra={"extra": {"subject": p.subject, "lease_id_suffix": body.lease_id[-8:], "request_id": request.headers.get("x-request-id")}},
        )
    except Exception:
        pass
    return {"ok": True, "lease_duration": res.get("lease_duration") if isinstance(res, dict) else None}

@router.post("/revoke")
async def revoke_lease(body: LeaseOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    try:
        client.sys.revoke(body.lease_id)
    except TypeError:
        client.sys.revoke_lease(body.lease_id)
    try:
        logging.getLogger("vault_mcp.response").info(
            "db_revoke",
            extra={"extra": {"subject": p.subject, "lease_id_suffix": body.lease_id[-8:], "request_id": request.headers.get("x-request-id")}},
        )
    except Exception:
        pass
    return {"ok": True}
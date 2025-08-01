from fastapi import Depends, Request
from .utils import Router as APIRouter
import logging
from ..models import SSHPassOp, SSHSignOp, Principal
from ..security import require_scopes
from ..vault import client_for_principal

router = APIRouter(prefix="/ssh", tags=["ssh"])

@router.post("/otp")
async def ssh_otp(op: SSHPassOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.ssh.generate_credential(name=op.role, username=op.username, ip=op.ip, port=op.port)
    data = res.get("data", {})
    out = {
        "ip": data.get("ip"),
        "username": data.get("username"),
        "port": data.get("port"),
        "otp": data.get("key") or data.get("otp"),
        "lease_id": res.get("lease_id"),
        "lease_duration": res.get("lease_duration"),
    }
    try:
        logging.getLogger("vault_mcp.response").info(
            "ssh_otp",
            extra={"extra": {"subject": p.subject, "role": op.role, "ip": op.ip, "user": op.username, "request_id": request.headers.get("x-request-id")}},
        )
    except Exception:
        pass
    return out

@router.post("/sign")
async def ssh_sign(op: SSHSignOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.ssh.sign_key(name=op.role, public_key=op.public_key, cert_type=op.cert_type, valid_principals=op.valid_principals, ttl=op.ttl)
    data = res.get("data", {})
    cert = data.get("signed_key") or data.get("signed_key_pem") or data.get("ssh_signature")
    try:
        logging.getLogger("vault_mcp.response").info(
            "ssh_sign",
            extra={"extra": {"subject": p.subject, "role": op.role, "cert_len": len(cert) if cert else 0, "request_id": request.headers.get("x-request-id")}},
        )
    except Exception:
        pass
    return {"certificate": cert}
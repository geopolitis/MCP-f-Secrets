from fastapi import Depends, Request
from .utils import Router as APIRouter
import logging
from ..models import TransitOp, TransitSign, TransitVerify, TransitRewrap, Principal
from ..security import require_scopes
from ..vault import client_for_principal

router = APIRouter(prefix="/transit", tags=["transit"])
@router.post("/encrypt")
async def transit_encrypt(op: TransitOp, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.transit.encrypt_data(name=op.key, plaintext=op.plaintext)
    out = {"ciphertext": res["data"]["ciphertext"]}
    try:
        logging.getLogger("vault_mcp.response").info("transit_encrypt", extra={"extra": {"subject": p.subject, "key": op.key, "ciphertext_len": len(out["ciphertext"]) if out.get("ciphertext") else 0, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return out

@router.post("/decrypt")
async def transit_decrypt(op: TransitOp, request: Request, p: Principal = Depends(require_scopes(["read"]))):
    client = client_for_principal(p)
    res = client.secrets.transit.decrypt_data(name=op.key, ciphertext=op.ciphertext)
    out = {"plaintext": res["data"]["plaintext"]}
    try:
        logging.getLogger("vault_mcp.response").info("transit_decrypt", extra={"extra": {"subject": p.subject, "key": op.key, "plaintext_len": len(out["plaintext"]) if out.get("plaintext") else 0, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return out

@router.post("/sign")
async def transit_sign(op: TransitSign, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.transit.sign_data(name=op.key, input=op.input, hash_algorithm=op.hash_algorithm, signature_algorithm=op.signature_algorithm)
    sig = res["data"]["signature"]
    try:
        logging.getLogger("vault_mcp.response").info("transit_sign", extra={"extra": {"subject": p.subject, "key": op.key, "sig_len": len(sig), "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return {"signature": sig}

@router.post("/verify")
async def transit_verify(op: TransitVerify, request: Request, p: Principal = Depends(require_scopes(["read"]))):
    client = client_for_principal(p)
    res = client.secrets.transit.verify_signed_data(name=op.key, input=op.input, signature=op.signature, hash_algorithm=op.hash_algorithm)
    valid = res["data"].get("valid", False)
    try:
        logging.getLogger("vault_mcp.response").info("transit_verify", extra={"extra": {"subject": p.subject, "key": op.key, "valid": valid, "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return {"valid": valid}

@router.get("/random", responses={400: {"description": "Invalid format (base64 or hex)"}})
async def transit_random(bytes: int = 32, format: str = "base64", request: Request = None, p: Principal = Depends(require_scopes(["read"]))):
    if format not in ("base64", "hex"):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid format. Use 'base64' or 'hex'.")
    client = client_for_principal(p)
    # hvac 2.3: only n_bytes is supported, returns base64
    res = client.secrets.transit.generate_random_bytes(n_bytes=bytes)
    b64 = res["data"].get("random_bytes", res["data"].get("random", ""))
    rnd = b64
    if format == "hex" and b64:
        import base64
        try:
            rnd = base64.b64decode(b64).hex()
        except Exception:
            from fastapi import HTTPException
            raise HTTPException(status_code=502, detail="Failed to convert random bytes to hex")
    out = {"random": rnd}
    try:
        logging.getLogger("vault_mcp.response").info(
            "transit_random",
            extra={
                "extra": {
                    "subject": p.subject,
                    "bytes": bytes,
                    "format": format,
                    "request_id": request.headers.get("x-request-id") if request else None,
                }
            },
        )
    except Exception:
        pass
    return out

@router.post("/rewrap")
async def transit_rewrap(op: TransitRewrap, request: Request, p: Principal = Depends(require_scopes(["write"]))):
    client = client_for_principal(p)
    res = client.secrets.transit.rewrap_data(name=op.key, ciphertext=op.ciphertext)
    ct = res["data"]["ciphertext"]
    try:
        logging.getLogger("vault_mcp.response").info("transit_rewrap", extra={"extra": {"subject": p.subject, "key": op.key, "ciphertext_len": len(ct), "request_id": request.headers.get("x-request-id")}})
    except Exception:
        pass
    return {"ciphertext": ct}
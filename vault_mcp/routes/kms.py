from fastapi import Depends, HTTPException, Request
import logging
from typing import Dict, Optional

from .utils import Router as APIRouter
from ..aws_kms import (
    KMSDisabledError,
    kms_enabled,
    kms_decrypt,
    kms_encrypt,
    kms_generate_data_key,
    kms_sign,
    kms_verify,
)
from ..models import (
    KmsDecryptRequest,
    KmsEncryptRequest,
    KmsDataKeyRequest,
    KmsSignRequest,
    KmsVerifyRequest,
    Principal,
)
from ..security import require_scopes
from ..settings import settings

router = APIRouter(prefix="/kms", tags=["kms"])
_resp_logger = logging.getLogger("vault_mcp.response")


def _ensure_enabled():
    if not kms_enabled():
        raise HTTPException(status_code=503, detail="AWS KMS support is disabled")


def _handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=502, detail=str(exc))


def _credentials_payload(body) -> Optional[Dict[str, Optional[str]]]:
    if getattr(body, "aws", None):
        data = body.aws.model_dump(exclude_none=True)
        return data or None
    return None


@router.post("/encrypt")
async def kms_encrypt_route(
    body: KmsEncryptRequest,
    request: Request,
    p: Principal = Depends(require_scopes(["write"])),
):
    _ensure_enabled()
    try:
        ciphertext = kms_encrypt(
            key_id=body.key_id,
            plaintext_b64=body.plaintext,
            encryption_context=body.encryption_context,
            grant_tokens=body.grant_tokens,
            credentials=_credentials_payload(body),
        )
        try:
            _resp_logger.info(
                "kms_encrypt",
                extra={
                    "extra": {
                        "subject": p.subject,
                        "key_id": body.key_id or settings.AWS_KMS_DEFAULT_KEY_ID,
                        "ciphertext_len": len(ciphertext),
                        "request_id": request.headers.get("x-request-id"),
                    }
                },
            )
        except Exception:
            pass
        return {"ciphertext": ciphertext}
    except KMSDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise _handle_error(exc)


@router.post("/decrypt")
async def kms_decrypt_route(
    body: KmsDecryptRequest,
    request: Request,
    p: Principal = Depends(require_scopes(["read"])),
):
    _ensure_enabled()
    try:
        plaintext = kms_decrypt(
            ciphertext_b64=body.ciphertext,
            encryption_context=body.encryption_context,
            grant_tokens=body.grant_tokens,
            credentials=_credentials_payload(body),
        )
        try:
            _resp_logger.info(
                "kms_decrypt",
                extra={
                    "extra": {
                        "subject": p.subject,
                        "plaintext_len": len(plaintext),
                        "request_id": request.headers.get("x-request-id"),
                    }
                },
            )
        except Exception:
            pass
        return {"plaintext": plaintext}
    except KMSDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise _handle_error(exc)


@router.post("/data-key")
async def kms_generate_data_key_route(
    body: KmsDataKeyRequest,
    request: Request,
    p: Principal = Depends(require_scopes(["write"])),
):
    _ensure_enabled()
    try:
        generated = kms_generate_data_key(
            key_id=body.key_id,
            key_spec=body.key_spec,
            number_of_bytes=body.number_of_bytes,
            encryption_context=body.encryption_context,
            grant_tokens=body.grant_tokens,
            credentials=_credentials_payload(body),
        )
        try:
            _resp_logger.info(
                "kms_data_key",
                extra={
                    "extra": {
                        "subject": p.subject,
                        "key_id": generated.get("key_id"),
                        "ciphertext_len": len(generated.get("ciphertext", "")),
                        "request_id": request.headers.get("x-request-id"),
                    }
                },
            )
        except Exception:
            pass
        return generated
    except KMSDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise _handle_error(exc)


@router.post("/sign")
async def kms_sign_route(
    body: KmsSignRequest,
    request: Request,
    p: Principal = Depends(require_scopes(["write"])),
):
    _ensure_enabled()
    try:
        signature = kms_sign(
            key_id=body.key_id,
            message_b64=body.message,
            message_digest_b64=body.message_digest,
            signing_algorithm=body.signing_algorithm,
            message_type=body.message_type,
            grant_tokens=body.grant_tokens,
            credentials=_credentials_payload(body),
        )
        try:
            _resp_logger.info(
                "kms_sign",
                extra={
                    "extra": {
                        "subject": p.subject,
                        "key_id": body.key_id or settings.AWS_KMS_DEFAULT_KEY_ID,
                        "signature_len": len(signature),
                        "request_id": request.headers.get("x-request-id"),
                    }
                },
            )
        except Exception:
            pass
        return {"signature": signature}
    except KMSDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise _handle_error(exc)


@router.post("/verify")
async def kms_verify_route(
    body: KmsVerifyRequest,
    request: Request,
    p: Principal = Depends(require_scopes(["read"])),
):
    _ensure_enabled()
    try:
        valid = kms_verify(
            key_id=body.key_id,
            signature_b64=body.signature,
            message_b64=body.message,
            message_digest_b64=body.message_digest,
            signing_algorithm=body.signing_algorithm,
            message_type=body.message_type,
            grant_tokens=body.grant_tokens,
            credentials=_credentials_payload(body),
        )
        try:
            _resp_logger.info(
                "kms_verify",
                extra={
                    "extra": {
                        "subject": p.subject,
                        "key_id": body.key_id or settings.AWS_KMS_DEFAULT_KEY_ID,
                        "valid": valid,
                        "request_id": request.headers.get("x-request-id"),
                    }
                },
            )
        except Exception:
            pass
        return {"valid": valid}
    except KMSDisabledError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise _handle_error(exc)

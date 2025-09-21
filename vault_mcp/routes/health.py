from datetime import datetime, timezone
import json

from fastapi import APIRouter
from fastapi.responses import Response

import hvac

from ..vault import new_vault_client
from ..settings import settings
from ..aws_kms import kms_health_check


def _json_ok(payload: dict, *, status_code: int = 200) -> Response:
    """Return JSON with canonical spacing expected by health checks."""
    return Response(
        content=json.dumps(payload, ensure_ascii=False, separators=(", ", ": ")),
        media_type="application/json",
        status_code=status_code,
    )


router = APIRouter()


@router.get("/healthz")
async def healthz():
    return _json_ok({"ok": True, "time": datetime.now(timezone.utc).isoformat()})


@router.get("/livez")
async def livez():
    return _json_ok({"ok": True})


@router.get("/readyz")
async def readyz():
    overall_ok = True
    vault_status = {"ok": True, "detail": "ready"}
    try:
        client = new_vault_client()
        if not client.is_authenticated():
            vault_status = {"ok": False, "detail": "Vault token unauthenticated"}
            overall_ok = False
    except hvac.exceptions.VaultError as exc:
        vault_status = {"ok": False, "detail": f"Vault error: {exc}"}
        overall_ok = False
    except Exception as exc:
        vault_status = {"ok": False, "detail": f"Vault error: {exc}"}
        overall_ok = False

    if settings.AWS_KMS_ENABLED:
        kms_ok, kms_detail = kms_health_check()
        kms_status = {"ok": kms_ok, "detail": kms_detail or ("ready" if kms_ok else "error")}
        if not kms_ok:
            overall_ok = False
    else:
        kms_status = {"ok": True, "detail": "disabled"}

    payload = {
        "ok": overall_ok,
        "time": datetime.now(timezone.utc).isoformat(),
        "vault": vault_status,
        "kms": kms_status,
    }
    status_code = 200 if overall_ok else 503
    return _json_ok(payload, status_code=status_code)

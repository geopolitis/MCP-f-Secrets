from datetime import datetime, timezone
import json

from fastapi import APIRouter
from fastapi.responses import Response

import hvac

from ..vault import new_vault_client


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
    try:
        client = new_vault_client()
        if not client.is_authenticated():
            return _json_ok({"ok": False, "vault": "unauthenticated"}, status_code=503)
        return _json_ok({"ok": True, "vault": "ready"})
    except hvac.exceptions.VaultError:
        return _json_ok({"ok": False, "vault": "error"}, status_code=503)
    except Exception:
        return _json_ok({"ok": False}, status_code=503)

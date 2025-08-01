from datetime import datetime, timezone
from fastapi import APIRouter, Response
from ..vault import new_vault_client
import hvac

router = APIRouter()
@router.get("/healthz")
async def healthz():
    return {"ok": True, "time": datetime.now(timezone.utc).isoformat()}

@router.get("/livez")
async def livez():
    return {"ok": True}

@router.get("/readyz")
async def readyz(response: Response):
    try:
        client = new_vault_client()
        if not client.is_authenticated():
            response.status_code = 503
            return {"ok": False, "vault": "unauthenticated"}
        return {"ok": True, "vault": "ready"}
    except hvac.exceptions.VaultError:
        response.status_code = 503
        return {"ok": False, "vault": "error"}
    except Exception:
        response.status_code = 503
        return {"ok": False}
import json
from typing import Optional
from fastapi.security import APIKeyHeader
from fastapi import Depends
from ..models import Principal
from ..settings import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
def _load_keymap():
    if not settings.API_KEYS_JSON:
        return {}
    try:
        return json.loads(settings.API_KEYS_JSON)
    except Exception:
        return {}
def verify_api_key(x_api_key: Optional[str] = Depends(api_key_header)) -> Optional[Principal]:
    if not settings.AUTH_API_KEY_ENABLED:
        return None
    if not x_api_key:
        return None
    subject = _load_keymap().get(x_api_key)
    if not subject:
        return None
    return Principal(
        subject=subject,
        scopes=["read", "write", "delete", "list"],
        vault_path_prefix=f"{settings.DEFAULT_PREFIX}/{subject}",
    )
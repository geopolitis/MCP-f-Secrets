import json
import os
from typing import Dict, Optional
from fastapi.security import APIKeyHeader
from fastapi import Depends
from ..models import Principal
from ..settings import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_KEYMAP_CACHE: dict[str, Dict[str, str]] = {}

def _load_keymap():
    raw = settings.API_KEYS_JSON or os.environ.get("API_KEYS_JSON") or ""
    if not raw:
        return {}

    cached = _KEYMAP_CACHE.get(raw)
    if cached is not None:
        return cached

    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(parsed, dict):
            result: Dict[str, str] = {str(k): str(v) for k, v in parsed.items()}
        else:
            result = {}
    except Exception:
        result = {}

    _KEYMAP_CACHE.clear()
    _KEYMAP_CACHE[raw] = result
    return result

def verify_api_key(x_api_key: Optional[str] = Depends(api_key_header)) -> Optional[Principal]:
    if not settings.AUTH_API_KEY_ENABLED:
        return None
    if not x_api_key:
        return None
    subject = _load_keymap().get(x_api_key.strip())
    if not subject:
        return None
    return Principal(
        subject=subject,
        scopes=["read", "write", "delete", "list"],
        vault_path_prefix=f"{settings.DEFAULT_PREFIX}/{subject}",
    )

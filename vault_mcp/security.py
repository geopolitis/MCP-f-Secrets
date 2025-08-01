from fastapi import Depends, HTTPException, status
from typing import Callable, List, Optional
from threading import Lock
from time import monotonic
from collections import defaultdict, deque
from .models import Principal
from .auth import verify_api_key, verify_jwt, verify_mtls
from .settings import settings

def get_principal(
    p1: Optional[Principal] = Depends(verify_api_key),
    p2: Optional[Principal] = Depends(verify_jwt),
    p3: Optional[Principal] = Depends(verify_mtls),
) -> Principal:
    p = p1 or p2 or p3
    if not p:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return p

def require_scopes(required: List[str]) -> Callable[[Principal], Principal]:
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        _rate_limit_check(p)
        if not set(required).issubset(set(p.scopes)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: missing scopes")
        return p
    return dep

def kv_safe_path(prefix: str, rel_path: str) -> str:
    safe = rel_path.strip("/").replace("..", "").replace("//", "/")
    return f"{prefix}/{safe}" if safe else prefix

_rl_lock = Lock()
_rl_map = defaultdict(deque)

def _rate_limit_check(p: Principal):
    if not settings.RATE_LIMIT_ENABLED:
        return
    key = f"sub:{p.subject}"
    now = monotonic(); window = settings.RATE_LIMIT_WINDOW_SECONDS; limit = settings.RATE_LIMIT_REQUESTS
    with _rl_lock:
        dq = _rl_map[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        dq.append(now)
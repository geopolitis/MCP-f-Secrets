from typing import Optional, Dict, Any
from fastapi import APIRouter


# Common error responses we want documented on most routes
COMMON_ERRORS: Dict[int, Dict[str, Any]] = {
    401: {"description": "Unauthorized"},
    403: {"description": "Forbidden (missing scopes or Vault policy)"},
    404: {"description": "Not found (e.g., InvalidPath in Vault)"},
    429: {"description": "Rate limit exceeded"},
    502: {"description": "Vault error"},
    503: {"description": "Vault unavailable / not ready"},
}


class Router(APIRouter):
    """APIRouter that automatically merges COMMON_ERRORS into route docs."""

    def add_api_route(self, path: str, endpoint, *, responses: Optional[Dict[int, Dict[str, Any]]] = None, **kwargs) -> None:
        merged = dict(COMMON_ERRORS)
        if responses:
            merged.update(responses)
        return super().add_api_route(path, endpoint, responses=merged, **kwargs)


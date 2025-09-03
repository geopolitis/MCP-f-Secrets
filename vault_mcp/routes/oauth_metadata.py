from fastapi import APIRouter
from ..settings import settings

router = APIRouter(tags=["oauth"])


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    # RFC 8414: Authorization Server Metadata (minimal placeholder)
    return {
        "issuer": settings.OAUTH_ISSUER or settings.JWT_ISSUER,
        "authorization_endpoint": settings.OAUTH_AUTHORIZATION_ENDPOINT,
        "token_endpoint": settings.OAUTH_TOKEN_ENDPOINT,
        "jwks_uri": settings.OAUTH_JWKS_URL or settings.JWT_JWKS_URL,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
    }


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    # RFC 9728: OAuth 2.0 Protected Resource Metadata (minimal placeholder)
    return {
        "resource": settings.OAUTH_RESOURCE_INDICATOR or "urn:example:vault-mcp",
        "authorization_servers": [settings.OAUTH_ISSUER] if settings.OAUTH_ISSUER else [],
        "bearer_methods_supported": ["bearer"],
        "resource_documentation": settings.OAUTH_RESOURCE_DOCS or None,
    }


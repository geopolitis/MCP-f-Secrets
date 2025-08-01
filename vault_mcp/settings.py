from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Vault connection
    VAULT_ADDR: str = "http://localhost:8200"
    VAULT_NAMESPACE: Optional[str] = None
    VAULT_TOKEN: Optional[str] = None
    VAULT_ROLE_ID: Optional[str] = None
    VAULT_SECRET_ID: Optional[str] = None
    KV_MOUNT: str = "secret"
    DEFAULT_PREFIX: str = "mcp"

    # Auth enable flags
    AUTH_API_KEY_ENABLED: bool = True
    AUTH_JWT_ENABLED: bool = True
    AUTH_MTLS_ENABLED: bool = False

    # API keys: JSON map token -> subject
    API_KEYS_JSON: Optional[str] = None

    # JWT base config
    JWT_ISSUER: str = "mcp-auth"
    JWT_AUDIENCE: str = "mcp-agents"
    JWT_HS256_SECRET: Optional[str] = None
    JWT_VALIDATE_ISSUER: bool = True
    JWT_VALIDATE_AUDIENCE: bool = True
    # RS256 / JWKS
    JWT_JWKS_URL: Optional[str] = None
    JWT_JWKS_FILE: Optional[str] = None
    JWT_JWKS_CACHE_SECONDS: int = 300
    JWT_REQUIRE_KID: bool = False

    # mTLS headers
    MTLS_IDENTITY_HEADER: str = "x-ssl-client-s-dn"
    MTLS_VERIFY_HEADER: Optional[str] = "x-ssl-client-verify"
    MTLS_SUBJECT_CN_PREFIX: str = "CN="

    # Child token issuance
    CHILD_TOKEN_ENABLED: bool = False
    CHILD_TOKEN_TTL: str = "90s"
    CHILD_TOKEN_POLICY_PREFIX: str = "mcp-agent-"

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()


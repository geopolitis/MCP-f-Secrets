from typing import Optional, Any, Dict
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource
import os
import json
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore

try:  # optional, only if installed
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

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

    # OAuth/OIDC metadata (optional, used for discovery only)
    OAUTH_ISSUER: Optional[str] = None
    OAUTH_AUTHORIZATION_ENDPOINT: Optional[str] = None
    OAUTH_TOKEN_ENDPOINT: Optional[str] = None
    OAUTH_JWKS_URL: Optional[str] = None
    OAUTH_RESOURCE_INDICATOR: Optional[str] = None
    OAUTH_RESOURCE_DOCS: Optional[str] = None

    # REST exposure toggle (for MCP-only deployments set to false)
    EXPOSE_REST_ROUTES: bool = True

    # CORS (for HTTP MCP Inspector). Comma-separated origins; e.g.,
    # "https://inspector.modelcontextprotocol.io,https://your-site".
    # If empty/None, CORS is disabled.
    CORS_ALLOW_ORIGINS: Optional[str] = None

    # SSE keepalive interval (seconds)
    SSE_KEEPALIVE_SECONDS: int = 15

    # AWS KMS integration
    AWS_KMS_ENABLED: bool = False
    AWS_REGION: Optional[str] = None
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_SESSION_TOKEN: Optional[str] = None
    AWS_KMS_ENDPOINT: Optional[str] = None
    AWS_KMS_DEFAULT_KEY_ID: Optional[str] = None

    # Do NOT auto-load .env; prefer environment variables and an optional config file.
    # A config file path can be provided via APP_CONFIG_FILE (JSON/TOML/YAML). Env vars override file.
    model_config = SettingsConfigDict(case_sensitive=True)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,  # environment has priority over file
            _FileConfigSource(cls),  # optional structured config file
            file_secret_settings,
        )


class _FileConfigSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        self._data: Dict[str, Any] = {}
        # Determine config path: APP_CONFIG_FILE or common defaults in CWD
        cfg = os.environ.get("APP_CONFIG_FILE") or os.environ.get("CONFIG_FILE")
        path: Optional[Path] = Path(cfg).expanduser().resolve() if cfg else None
        if not path:
            for name in ("config.toml", "config.json", "config.yaml", "config.yml"):
                p = Path.cwd() / name
                if p.exists():
                    path = p.resolve()
                    break
        if not path or not path.exists():
            return
        try:
            data: Dict[str, Any] = {}
            suffix = path.suffix.lower()
            if suffix == ".json":
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f) or {}
            elif suffix == ".toml" and tomllib is not None:
                with path.open("rb") as f:
                    data = tomllib.load(f) or {}
            elif suffix in (".yaml", ".yml") and yaml is not None:
                with path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            # Normalize to uppercase keys
            if isinstance(data, dict):
                self._data = {str(k).upper(): v for k, v in data.items()}
        except Exception:
            self._data = {}

    def get_field_value(self, field_name: str, field, value: Any) -> tuple[Any, str | None]:
        if not self._data:
            return None, None
        key = field_name
        if key in self._data:
            return self._data[key], "file"
        # also try uppercase form
        up = key.upper()
        if up in self._data:
            return self._data[up], "file"
        return None, None

    def __call__(self) -> Dict[str, Any]:
        # Return the full mapping for compatibility. Pydantic may or may not use this
        # depending on version, but it must be present to satisfy the abstract contract.
        return dict(self._data) if getattr(self, "_data", None) else {}


settings = Settings()

import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def app():
    # Ensure predictable settings for tests
    # Ensure repo root is on sys.path so 'vault_mcp' is importable
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    os.environ["AUTH_API_KEY_ENABLED"] = "true"
    os.environ.pop("API_KEYS_JSON", None)
    api_keys_json = '{"dev-api-key":"agent_api","dev-key":"agent_api"}'
    os.environ["API_KEYS_JSON"] = api_keys_json
    os.environ["CHILD_TOKEN_ENABLED"] = "false"
    os.environ["SSE_KEEPALIVE_SECONDS"] = "1"
    os.environ.setdefault("AWS_KMS_ENABLED", "true")
    os.environ.setdefault("AWS_REGION", "us-east-1")

    from vault_mcp.app import create_app
    from vault_mcp.settings import settings as _settings

    # Align the singleton settings instance with the environment for tests that read it directly
    _settings.API_KEYS_JSON = api_keys_json

    return create_app()


@pytest.fixture()
def client(app):
    return TestClient(app)

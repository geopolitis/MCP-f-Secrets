from typing import Optional, Dict, Any, List
import hvac
from .settings import settings
from .models import Principal

def new_vault_client() -> hvac.Client:
    client = hvac.Client(url=settings.VAULT_ADDR, namespace=settings.VAULT_NAMESPACE or None)
    if settings.VAULT_TOKEN:
        client.token = settings.VAULT_TOKEN
    elif settings.VAULT_ROLE_ID and settings.VAULT_SECRET_ID:
        resp = client.auth.approle.login(role_id=settings.VAULT_ROLE_ID, secret_id=settings.VAULT_SECRET_ID)
        client.token = resp["auth"]["client_token"]
    else:
        raise RuntimeError("No Vault auth configured (token or AppRole required)")
    if not client.is_authenticated():
        raise RuntimeError("Vault auth failed")
    return client

def client_for_principal(principal: Principal) -> hvac.Client:
    parent = new_vault_client()
    if not settings.CHILD_TOKEN_ENABLED:
        return parent
    policy_name = f"{settings.CHILD_TOKEN_POLICY_PREFIX}{principal.subject}"
    res = parent.auth.token.create(policies=[policy_name], ttl=settings.CHILD_TOKEN_TTL, display_name=f"mcp-{principal.subject}")
    token = (
        (res.get("auth") or {}).get("client_token")
        or (res.get("auth") or {}).get("token")
        or (res.get("data") or {}).get("token")
        or res.get("client_token")
    )
    if not token:
        return parent
    child = hvac.Client(url=settings.VAULT_ADDR, namespace=settings.VAULT_NAMESPACE or None)
    child.token = token
    return child

def kv_read(client: hvac.Client, path: str, version: Optional[int] = None) -> Dict[str, Any]:
    return client.secrets.kv.v2.read_secret_version(mount_point=settings.KV_MOUNT, path=path, version=version)

def kv_write(client: hvac.Client, path: str, data: Dict[str, Any], cas: Optional[int] = None):
    return client.secrets.kv.v2.create_or_update_secret(mount_point=settings.KV_MOUNT, path=path, secret=data, cas=cas)

def kv_delete_latest(client: hvac.Client, path: str):
    return client.secrets.kv.v2.delete_latest_version_of_secret(mount_point=settings.KV_MOUNT, path=path)

def kv_list(client: hvac.Client, path: str) -> List[str]:
    res = client.secrets.kv.v2.list_secrets(mount_point=settings.KV_MOUNT, path=path)
    return res.get("data", {}).get("keys", [])

def kv_undelete(client: hvac.Client, path: str, versions: List[int]):
    return client.secrets.kv.v2.undelete_secret_versions(mount_point=settings.KV_MOUNT, path=path, versions=versions)

def kv_destroy(client: hvac.Client, path: str, versions: List[int]):
    return client.secrets.kv.v2.destroy_secret_versions(mount_point=settings.KV_MOUNT, path=path, versions=versions)
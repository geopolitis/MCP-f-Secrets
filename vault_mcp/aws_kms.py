"""Helpers for interacting with AWS KMS."""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, NoRegionError

from .settings import settings


class KMSDisabledError(RuntimeError):
    """Raised when AWS KMS support is disabled in configuration."""


def _get_env_bool(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return None


def _kms_enabled() -> bool:
    env_value = _get_env_bool("AWS_KMS_ENABLED")
    if env_value is not None:
        return env_value
    return bool(settings.AWS_KMS_ENABLED)


def kms_enabled() -> bool:
    """Return whether AWS KMS support is enabled via settings or environment."""
    return _kms_enabled()


def _ensure_enabled() -> None:
    if not _kms_enabled():
        raise KMSDisabledError("AWS KMS support is disabled")


def _build_session_kwargs(
    access_key_id: Optional[str],
    secret_access_key: Optional[str],
    session_token: Optional[str],
) -> Dict[str, str]:
    kwargs: Dict[str, str] = {}
    if access_key_id and secret_access_key:
        kwargs["aws_access_key_id"] = access_key_id
        kwargs["aws_secret_access_key"] = secret_access_key
        if session_token:
            kwargs["aws_session_token"] = session_token
    return kwargs


@lru_cache(maxsize=1)
def _kms_client_default():
    _ensure_enabled()
    session_kwargs = _build_session_kwargs(
        settings.AWS_ACCESS_KEY_ID,
        settings.AWS_SECRET_ACCESS_KEY,
        settings.AWS_SESSION_TOKEN,
    )
    if settings.AWS_REGION:
        session_kwargs.setdefault("region_name", settings.AWS_REGION)
    session = boto3.session.Session(**session_kwargs)
    client_kwargs: Dict[str, str] = {}
    if settings.AWS_REGION:
        client_kwargs["region_name"] = settings.AWS_REGION
    if settings.AWS_KMS_ENDPOINT:
        client_kwargs["endpoint_url"] = settings.AWS_KMS_ENDPOINT
    return session.client("kms", **client_kwargs)


def _kms_client(override: Optional[Dict[str, Optional[str]]] = None):
    _ensure_enabled()
    if override:
        session_kwargs = _build_session_kwargs(
            override.get("access_key_id"),
            override.get("secret_access_key"),
            override.get("session_token"),
        )
        region = override.get("region") or settings.AWS_REGION
        if region:
            session_kwargs.setdefault("region_name", region)
        session = boto3.session.Session(**session_kwargs)
        client_kwargs: Dict[str, str] = {}
        if region:
            client_kwargs["region_name"] = region
        endpoint = override.get("endpoint") or settings.AWS_KMS_ENDPOINT
        if endpoint:
            client_kwargs["endpoint_url"] = endpoint
        return session.client("kms", **client_kwargs)
    return _kms_client_default()


def reset_kms_client_cache() -> None:
    """Clear the cached KMS client (useful for tests)."""
    try:
        _kms_client_default.cache_clear()  # type: ignore[attr-defined]
    except Exception:
        pass


def kms_health_check() -> Tuple[bool, str]:
    """Return (ok, detail) describing the ability to construct a KMS client."""
    if not _kms_enabled():
        return True, "disabled"
    try:
        _kms_client()
        return True, "ready"
    except KMSDisabledError:
        return False, "disabled"
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        return False, str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def _resolve_key_id(key_id: Optional[str]) -> str:
    result = key_id or settings.AWS_KMS_DEFAULT_KEY_ID
    if not result:
        raise ValueError("key_id is required (no AWS_KMS_DEFAULT_KEY_ID configured)")
    return result


def _b64decode(data: str, *, field: str) -> bytes:
    if data is None:
        raise ValueError(f"{field} is required")
    try:
        return base64.b64decode(data)
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError(f"{field} must be base64 encoded") from exc


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def kms_encrypt(
    *,
    key_id: Optional[str],
    plaintext_b64: str,
    encryption_context: Optional[Dict[str, str]] = None,
    grant_tokens: Optional[List[str]] = None,
    credentials: Optional[Dict[str, Optional[str]]] = None,
) -> str:
    try:
        client = _kms_client(credentials)
        resolved_key = _resolve_key_id(key_id)
        payload = {
            "KeyId": resolved_key,
            "Plaintext": _b64decode(plaintext_b64, field="plaintext"),
        }
        if encryption_context:
            payload["EncryptionContext"] = encryption_context
        if grant_tokens:
            payload["GrantTokens"] = grant_tokens
        response = client.encrypt(**payload)
        return _b64encode(response["CiphertextBlob"])
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        raise RuntimeError(str(exc)) from exc


def kms_decrypt(
    *,
    ciphertext_b64: str,
    encryption_context: Optional[Dict[str, str]] = None,
    grant_tokens: Optional[List[str]] = None,
    credentials: Optional[Dict[str, Optional[str]]] = None,
) -> str:
    try:
        client = _kms_client(credentials)
        payload = {
            "CiphertextBlob": _b64decode(ciphertext_b64, field="ciphertext"),
        }
        if encryption_context:
            payload["EncryptionContext"] = encryption_context
        if grant_tokens:
            payload["GrantTokens"] = grant_tokens
        response = client.decrypt(**payload)
        return _b64encode(response["Plaintext"])
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        raise RuntimeError(str(exc)) from exc


def kms_generate_data_key(
    *,
    key_id: Optional[str],
    key_spec: Optional[str] = None,
    number_of_bytes: Optional[int] = None,
    encryption_context: Optional[Dict[str, str]] = None,
    grant_tokens: Optional[List[str]] = None,
    credentials: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, str]:
    if not key_spec and not number_of_bytes:
        raise ValueError("Either key_spec or number_of_bytes must be provided")
    try:
        client = _kms_client(credentials)
        resolved_key = _resolve_key_id(key_id)
        payload: Dict[str, object] = {"KeyId": resolved_key}
        if key_spec:
            payload["KeySpec"] = key_spec
        if number_of_bytes:
            payload["NumberOfBytes"] = int(number_of_bytes)
        if encryption_context:
            payload["EncryptionContext"] = encryption_context
        if grant_tokens:
            payload["GrantTokens"] = grant_tokens
        response = client.generate_data_key(**payload)
        key_id_value = resolved_key
        resp_key = response.get("KeyId")
        if isinstance(resp_key, str) and resolved_key in resp_key:
            key_id_value = resolved_key
        elif isinstance(resp_key, str):
            key_id_value = resp_key
        return {
            "key_id": key_id_value,
            "ciphertext": _b64encode(response["CiphertextBlob"]),
            "plaintext": _b64encode(response["Plaintext"]),
        }
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        raise RuntimeError(str(exc)) from exc


def kms_sign(
    *,
    key_id: Optional[str],
    message_b64: Optional[str] = None,
    message_digest_b64: Optional[str] = None,
    signing_algorithm: str,
    message_type: Optional[str] = None,
    grant_tokens: Optional[List[str]] = None,
    credentials: Optional[Dict[str, Optional[str]]] = None,
) -> str:
    if not message_b64 and not message_digest_b64:
        raise ValueError("Either message or message_digest must be provided")
    try:
        client = _kms_client(credentials)
        resolved_key = _resolve_key_id(key_id)
        payload: Dict[str, object] = {
            "KeyId": resolved_key,
            "SigningAlgorithm": signing_algorithm,
        }
        if message_b64:
            payload["Message"] = _b64decode(message_b64, field="message")
        if message_digest_b64:
            payload["MessageDigest"] = _b64decode(message_digest_b64, field="message_digest")
        if message_type:
            payload["MessageType"] = message_type
        if grant_tokens:
            payload["GrantTokens"] = grant_tokens
        response = client.sign(**payload)
        return _b64encode(response["Signature"])
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        raise RuntimeError(str(exc)) from exc


def kms_verify(
    *,
    key_id: Optional[str],
    signature_b64: str,
    message_b64: Optional[str] = None,
    message_digest_b64: Optional[str] = None,
    signing_algorithm: str,
    message_type: Optional[str] = None,
    grant_tokens: Optional[List[str]] = None,
    credentials: Optional[Dict[str, Optional[str]]] = None,
) -> bool:
    if not message_b64 and not message_digest_b64:
        raise ValueError("Either message or message_digest must be provided")
    try:
        client = _kms_client(credentials)
        payload: Dict[str, object] = {
            "KeyId": _resolve_key_id(key_id),
            "Signature": _b64decode(signature_b64, field="signature"),
            "SigningAlgorithm": signing_algorithm,
        }
        if message_b64:
            payload["Message"] = _b64decode(message_b64, field="message")
        if message_digest_b64:
            payload["MessageDigest"] = _b64decode(message_digest_b64, field="message_digest")
        if message_type:
            payload["MessageType"] = message_type
        if grant_tokens:
            payload["GrantTokens"] = grant_tokens
        response = client.verify(**payload)
        return bool(response.get("SignatureValid", False))
    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        raise RuntimeError(str(exc)) from exc

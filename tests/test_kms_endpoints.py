import base64

import boto3
import pytest
from moto import mock_aws

from vault_mcp import aws_kms
from vault_mcp import settings as settings_module

HEADERS = {"X-API-Key": "dev-key"}


@pytest.fixture(autouse=True)
def reset_kms_cache():
    aws_kms.reset_kms_client_cache()
    yield
    aws_kms.reset_kms_client_cache()


@mock_aws
def test_kms_encrypt_decrypt_roundtrip(client):
    region = settings_module.settings.AWS_REGION or "us-east-1"
    kms = boto3.client("kms", region_name=region)
    key_metadata = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")
    key_id = key_metadata["KeyMetadata"]["KeyId"]

    # Use default key id to minimise payload boilerplate
    previous_default = settings_module.settings.AWS_KMS_DEFAULT_KEY_ID
    settings_module.settings.AWS_KMS_DEFAULT_KEY_ID = key_id
    try:
        aws_kms.reset_kms_client_cache()
        plaintext = base64.b64encode(b"hello-aws-kms").decode()
    enc = client.post(
        "/kms/encrypt",
        headers=HEADERS,
        json={"plaintext": plaintext, "aws": {"region": region}},
    )
        assert enc.status_code == 200
        ciphertext = enc.json()["ciphertext"]
    dec = client.post(
        "/kms/decrypt",
        headers=HEADERS,
        json={"ciphertext": ciphertext, "aws": {"region": region}},
    )
        assert dec.status_code == 200
        decrypted = base64.b64decode(dec.json()["plaintext"])
        assert decrypted == b"hello-aws-kms"
    finally:
        settings_module.settings.AWS_KMS_DEFAULT_KEY_ID = previous_default


@mock_aws
def test_kms_data_key_and_sign_verify(client):
    region = settings_module.settings.AWS_REGION or "us-east-1"
    kms = boto3.client("kms", region_name=region)

    enc_key = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    sign_key = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_2048")["KeyMetadata"]["KeyId"]

    data_key_resp = client.post(
        "/kms/data-key",
        headers=HEADERS,
        json={"key_id": enc_key, "key_spec": "AES_256", "aws": {"region": region}},
    )
    assert data_key_resp.status_code == 200
    body = data_key_resp.json()
    assert body["key_id"] == enc_key
    assert base64.b64decode(body["plaintext"]) != b""  # plaintext returned
    assert base64.b64decode(body["ciphertext"]) != b""

    message = base64.b64encode(b"kms-sign-payload").decode()
    sign_resp = client.post(
        "/kms/sign",
        headers=HEADERS,
        json={
            "key_id": sign_key,
            "message": message,
            "signing_algorithm": "RSASSA_PSS_SHA_256",
            "aws": {"region": region},
        },
    )
    assert sign_resp.status_code == 200
    signature = sign_resp.json()["signature"]

    verify_resp = client.post(
        "/kms/verify",
        headers=HEADERS,
        json={
            "key_id": sign_key,
            "message": message,
            "signature": signature,
            "signing_algorithm": "RSASSA_PSS_SHA_256",
            "aws": {"region": region},
        },
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

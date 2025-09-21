from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator

class Principal(BaseModel):
    subject: str
    scopes: List[str] = Field(default_factory=list)
    vault_path_prefix: str

class SecretWrite(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = None

class SecretRead(BaseModel):
    data: Dict[str, Any]
    version: Optional[int] = None
    created_time: Optional[str] = None

class VersionsOp(BaseModel):
    versions: List[int]

class TransitOp(BaseModel):
    key: str
    plaintext: Optional[str] = None
    ciphertext: Optional[str] = None

class TransitSign(BaseModel):
    key: str
    input: str
    hash_algorithm: Optional[str] = None
    signature_algorithm: Optional[str] = None

class TransitVerify(BaseModel):
    key: str
    input: str
    signature: str
    hash_algorithm: Optional[str] = None

class TransitRandom(BaseModel):
    bytes: int = 32
    format: Optional[str] = None

class TransitRewrap(BaseModel):
    key: str
    ciphertext: str

class DbCredsIssue(BaseModel):
    role: str

class LeaseOp(BaseModel):
    lease_id: str
    increment: Optional[int] = None

class SSHPassOp(BaseModel):
    role: str
    ip: str
    username: str
    port: Optional[int] = None

class SSHSignOp(BaseModel):
    role: str
    public_key: str
    cert_type: Optional[str] = "user"
    valid_principals: Optional[str] = None
    ttl: Optional[str] = None


class AwsCredentialOverride(BaseModel):
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    region: Optional[str] = None
    endpoint: Optional[str] = None


class KmsEncryptRequest(BaseModel):
    key_id: Optional[str] = None
    plaintext: str
    encryption_context: Optional[Dict[str, str]] = None
    grant_tokens: Optional[List[str]] = None
    aws: Optional[AwsCredentialOverride] = None


class KmsDecryptRequest(BaseModel):
    ciphertext: str
    encryption_context: Optional[Dict[str, str]] = None
    grant_tokens: Optional[List[str]] = None
    aws: Optional[AwsCredentialOverride] = None


class KmsDataKeyRequest(BaseModel):
    key_id: Optional[str] = None
    key_spec: Optional[str] = None
    number_of_bytes: Optional[int] = Field(default=None, ge=1)
    encryption_context: Optional[Dict[str, str]] = None
    grant_tokens: Optional[List[str]] = None
    aws: Optional[AwsCredentialOverride] = None

    @model_validator(mode="after")
    def validate_choice(cls, values: "KmsDataKeyRequest") -> "KmsDataKeyRequest":
        if not values.key_spec and not values.number_of_bytes:
            raise ValueError("Either key_spec or number_of_bytes must be provided")
        return values


class KmsSignRequest(BaseModel):
    key_id: Optional[str] = None
    message: Optional[str] = None
    message_digest: Optional[str] = None
    signing_algorithm: str
    message_type: Optional[str] = None
    grant_tokens: Optional[List[str]] = None
    aws: Optional[AwsCredentialOverride] = None

    @model_validator(mode="after")
    def ensure_payload(cls, values: "KmsSignRequest") -> "KmsSignRequest":
        if not values.message and not values.message_digest:
            raise ValueError("Either message or message_digest is required")
        return values


class KmsVerifyRequest(BaseModel):
    key_id: Optional[str] = None
    signature: str
    message: Optional[str] = None
    message_digest: Optional[str] = None
    signing_algorithm: str
    message_type: Optional[str] = None
    grant_tokens: Optional[List[str]] = None
    aws: Optional[AwsCredentialOverride] = None

    @model_validator(mode="after")
    def ensure_payload(cls, values: "KmsVerifyRequest") -> "KmsVerifyRequest":
        if not values.message and not values.message_digest:
            raise ValueError("Either message or message_digest is required")
        return values

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

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
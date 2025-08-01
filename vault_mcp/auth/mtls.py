from typing import Optional
from fastapi import Header, Request
from ..models import Principal
from ..settings import settings

def _extract_subject_from_dn(dn: str) -> Optional[str]:
    parts = [p.strip() for p in dn.split(",")]
    for p in parts:
        if p.startswith(settings.MTLS_SUBJECT_CN_PREFIX):
            return p[len(settings.MTLS_SUBJECT_CN_PREFIX):]
    return None

def verify_mtls(request: Request, client_dn: Optional[str] = Header(None)) -> Optional[Principal]:
    if not settings.AUTH_MTLS_ENABLED:
        return None
    hdr_name = settings.MTLS_IDENTITY_HEADER.lower()
    hdr_verify = settings.MTLS_VERIFY_HEADER.lower() if settings.MTLS_VERIFY_HEADER else None
    dn = request.headers.get(hdr_name) or client_dn
    if not dn:
        return None
    if hdr_verify:
        v = request.headers.get(hdr_verify)
        if v and not v.lower().startswith("success"):
            return None
    subject = _extract_subject_from_dn(dn) or dn
    return Principal(subject=subject, scopes=["read", "write", "delete", "list"], vault_path_prefix=f"{settings.DEFAULT_PREFIX}/{subject}")
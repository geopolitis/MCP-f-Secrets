import time
import base64
from typing import Optional, Dict, Any
from fastapi import Header
import httpx
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from ..models import Principal
from ..settings import settings

_jwks_cache: Dict[str, Dict[str, Any]] = {}

def _get_jwks_from_url(url: str) -> Optional[Dict[str, Any]]:
    now = int(time.time())
    entry = _jwks_cache.get(url)
    if entry and entry.get("expires", 0) > now:
        return entry.get("jwks")
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            jwks = resp.json()
            _jwks_cache[url] = {"jwks": jwks, "expires": now + max(30, settings.JWT_JWKS_CACHE_SECONDS)}
            return jwks
    except Exception:
        return entry.get("jwks") if entry else None

def _get_jwks() -> Optional[Dict[str, Any]]:
    if settings.JWT_JWKS_FILE:
        try:
            import json, os
            if os.path.exists(settings.JWT_JWKS_FILE):
                with open(settings.JWT_JWKS_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
    if settings.JWT_JWKS_URL:
        return _get_jwks_from_url(settings.JWT_JWKS_URL)
    return None

def _select_jwk(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    if settings.JWT_REQUIRE_KID and not kid:
        return None
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
    for k in keys:
        if k.get("kty") == "RSA" and k.get("use", "sig") == "sig":
            return k
    return None

def _rsa_pem_from_jwk(jwk: Dict[str, Any]) -> Optional[bytes]:
    try:
        if jwk.get("kty") != "RSA":
            return None
        n_b64 = jwk.get("n"); e_b64 = jwk.get("e")
        if not n_b64 or not e_b64:
            return None
        def b64url_to_int(s: str) -> int:
            pad = '=' * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(s + pad), 'big')
        n = b64url_to_int(n_b64); e = b64url_to_int(e_b64)
        pub_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        pub_key = pub_numbers.public_key()
        return pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None

def verify_jwt(authorization: Optional[str] = Header(None)) -> Optional[Principal]:
    if not settings.AUTH_JWT_ENABLED:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    try:
        hdr = jwt.get_unverified_header(token)
    except JWTError:
        return None
    alg = (hdr or {}).get("alg"); kid = (hdr or {}).get("kid")
    try:
        options = {"verify_aud": settings.JWT_VALIDATE_AUDIENCE, "verify_iss": settings.JWT_VALIDATE_ISSUER}
        kwargs: Dict[str, Any] = {"options": options}
        if settings.JWT_VALIDATE_AUDIENCE:
            kwargs["audience"] = settings.JWT_AUDIENCE
        if settings.JWT_VALIDATE_ISSUER:
            kwargs["issuer"] = settings.JWT_ISSUER
        if alg == "RS256":
            jwks = _get_jwks()
            if not jwks:
                return None
            jwk = _select_jwk(jwks, kid)
            if not jwk:
                return None
            pem = _rsa_pem_from_jwk(jwk)
            if not pem:
                return None
            payload = jwt.decode(token, pem.decode("ascii"), algorithms=["RS256"], **kwargs)
        elif alg == "HS256" and settings.JWT_HS256_SECRET:
            payload = jwt.decode(token, settings.JWT_HS256_SECRET, algorithms=["HS256"], **kwargs)
        else:
            return None

        sub = payload.get("sub"); scopes = payload.get("scopes", [])
        if not sub:
            return None
        return Principal(subject=sub, scopes=scopes, vault_path_prefix=f"{settings.DEFAULT_PREFIX}/{sub}")
    except JWTError:
        return None
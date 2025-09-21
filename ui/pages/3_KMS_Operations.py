"""Dedicated AWS KMS operations helper."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Dict, Optional

import httpx
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state, update_auth_state  # noqa: E402


st.title("AWS KMS Operations")
st.caption("Configure temporary credentials and call KMS encrypt/decrypt, data-key, and signing APIs")

auth_state = get_auth_state()


def _aws_override() -> Optional[Dict[str, str]]:
    data = {
        "access_key_id": auth_state.aws_access_key_id,
        "secret_access_key": auth_state.aws_secret_access_key,
        "session_token": auth_state.aws_session_token,
        "region": auth_state.aws_region,
        "endpoint": auth_state.aws_kms_endpoint,
    }
    filtered = {k: v for k, v in data.items() if v}
    return filtered or None


def _post(path: str, payload: Dict[str, object]) -> Dict[str, object]:
    override = _aws_override()
    if override:
        payload["aws"] = override
    headers = {k: v for k, v in [("X-API-Key", auth_state.api_key), ("Authorization", f"Bearer {auth_state.jwt}" if auth_state.jwt else None)] if v}
    resp = httpx.post(
        f"{auth_state.host}{path}",
        headers=headers,
        json=payload,
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def _credentials_form() -> None:
    with st.form("kms-credentials"):
        st.subheader("Credentials")
        st.write("Provide temporary AWS credentials or leave blank to use the server defaults.")
        col_a, col_b = st.columns(2)
        with col_a:
            region = st.text_input("AWS region", value=auth_state.aws_region or "")
            access_key = st.text_input("Access key ID", value=auth_state.aws_access_key_id or "")
            session_token = st.text_input("Session token", value=auth_state.aws_session_token or "", help="Optional STS session token")
        with col_b:
            endpoint = st.text_input("KMS endpoint override", value=auth_state.aws_kms_endpoint or "", help="Optional (e.g. LocalStack)")
            secret_key = st.text_input("Secret access key", value=auth_state.aws_secret_access_key or "", type="password")
        if st.form_submit_button("Save credentials"):
            update_auth_state(
                aws_region=region or None,
                aws_access_key_id=access_key or None,
                aws_secret_access_key=secret_key or None,
                aws_session_token=session_token or None,
                aws_kms_endpoint=endpoint or None,
            )
            st.success("Credentials updated for this UI session.")
    override = _aws_override()
    if override:
        redacted = dict(override)
        if "secret_access_key" in redacted:
            redacted["secret_access_key"] = "***"
        st.info(f"Using override: {json.dumps(redacted, indent=2)}")
    else:
        st.info("Calls will rely on the server's configured AWS credentials (no override set).")


AWS_FIELD_HELP = "Optional JSON object mapping keys to strings (e.g. {\"env\":\"prod\"})."


def _tab_encrypt() -> None:
    st.subheader("Encrypt")
    enc_key_id = st.text_input("Key ID", help="Optional; falls back to server default", key="enc-key")
    enc_plain = st.text_area("Plaintext", value="", height=120, key="enc-plain")
    enc_context_text = st.text_area("Encryption context", value="", height=120, help=AWS_FIELD_HELP, key="enc-ctx")
    enc_auto = st.checkbox("Base64 encode plaintext automatically", value=True, key="enc-auto")
    if st.button("Encrypt", key="do-encrypt"):
        try:
            context = json.loads(enc_context_text or "{}") if enc_context_text else None
        except json.JSONDecodeError as exc:
            st.error(f"Invalid encryption context JSON: {exc}")
        else:
            payload: Dict[str, object] = {
                "plaintext": base64.b64encode(enc_plain.encode()).decode() if enc_auto else enc_plain,
            }
            if enc_key_id:
                payload["key_id"] = enc_key_id
            if context:
                payload["encryption_context"] = context
            try:
                st.json(_post("/kms/encrypt", payload))
            except Exception as exc:
                st.error(f"Encrypt failed: {exc}")

    st.subheader("Decrypt")
    dec_cipher = st.text_area("Ciphertext (base64)", value="", height=120, key="dec-cipher")
    dec_context_text = st.text_area("Encryption context", value="", height=120, help=AWS_FIELD_HELP, key="dec-ctx")
    dec_decode = st.checkbox("Decode plaintext from base64", value=True, key="dec-auto")
    if st.button("Decrypt", key="do-decrypt"):
        try:
            context = json.loads(dec_context_text or "{}") if dec_context_text else None
        except json.JSONDecodeError as exc:
            st.error(f"Invalid encryption context JSON: {exc}")
        else:
            payload: Dict[str, object] = {"ciphertext": dec_cipher}
            if context:
                payload["encryption_context"] = context
            try:
                body = _post("/kms/decrypt", payload)
                if dec_decode and body.get("plaintext"):
                    try:
                        body["plaintext_decoded"] = base64.b64decode(body["plaintext"]).decode()
                    except Exception:
                        body["plaintext_decoded"] = "<decode failed>"
                st.json(body)
            except Exception as exc:
                st.error(f"Decrypt failed: {exc}")


def _tab_data_key() -> None:
    st.subheader("Generate data key")
    dk_key_id = st.text_input("Key ID", key="dk-key")
    dk_key_spec = st.selectbox("Key spec", ["", "AES_256", "AES_128"], index=1, key="dk-spec")
    dk_bytes = st.number_input("Number of bytes", min_value=0, max_value=1024, value=0, key="dk-bytes")
    dk_context_text = st.text_area("Encryption context", value="", height=120, help=AWS_FIELD_HELP, key="dk-ctx")
    if st.button("Generate data key", key="do-datakey"):
        if not dk_key_spec and not dk_bytes:
            st.error("Provide a key spec or number of bytes")
        else:
            try:
                context = json.loads(dk_context_text or "{}") if dk_context_text else None
            except json.JSONDecodeError as exc:
                st.error(f"Invalid encryption context JSON: {exc}")
            else:
                payload: Dict[str, object] = {}
                if dk_key_id:
                    payload["key_id"] = dk_key_id
                if dk_key_spec:
                    payload["key_spec"] = dk_key_spec
                if not dk_key_spec and dk_bytes:
                    payload["number_of_bytes"] = int(dk_bytes)
                if context:
                    payload["encryption_context"] = context
                try:
                    st.json(_post("/kms/data-key", payload))
                except Exception as exc:
                    st.error(f"Generate data key failed: {exc}")


def _tab_sign_verify() -> None:
    st.subheader("Sign message")
    sign_key_id = st.text_input("Key ID", key="sign-key")
    sign_message = st.text_area("Message", value="", height=120, help="Optional if digest provided", key="sign-msg")
    sign_digest = st.text_input("Message digest (base64)", value="", key="sign-digest")
    sign_algorithm = st.text_input("Signing algorithm", value="RSASSA_PSS_SHA_256", key="sign-alg")
    sign_type = st.selectbox("Message type", ["", "RAW", "DIGEST"], index=0, key="sign-type")
    sign_grants = st.text_area("Grant tokens", value="", height=80, help="Optional JSON array", key="sign-grants")
    sign_auto = st.checkbox("Base64 encode message automatically", value=True, key="sign-auto")
    if st.button("Sign", key="do-sign"):
        if not sign_digest and not sign_message:
            st.error("Provide a message or message digest")
        else:
            try:
                grants = json.loads(sign_grants or "[]") if sign_grants else None
            except json.JSONDecodeError as exc:
                st.error(f"Invalid grant token JSON: {exc}")
            else:
                payload: Dict[str, object] = {"signing_algorithm": sign_algorithm}
                if sign_key_id:
                    payload["key_id"] = sign_key_id
                if sign_digest:
                    payload["message_digest"] = sign_digest
                else:
                    payload["message"] = base64.b64encode(sign_message.encode()).decode() if sign_auto else sign_message
                if sign_type:
                    payload["message_type"] = sign_type
                if grants:
                    payload["grant_tokens"] = grants
                try:
                    st.json(_post("/kms/sign", payload))
                except Exception as exc:
                    st.error(f"Sign failed: {exc}")

    st.subheader("Verify signature")
    verify_signature = st.text_area("Signature (base64)", value="", height=120, key="verify-sig")
    verify_key_id = st.text_input("Key ID", key="verify-key")
    verify_message = st.text_area("Message", value="", height=120, help="Optional if digest provided", key="verify-msg")
    verify_digest = st.text_input("Message digest (base64)", value="", key="verify-digest")
    verify_algorithm = st.text_input("Signing algorithm", value="RSASSA_PSS_SHA_256", key="verify-alg")
    verify_type = st.selectbox("Message type", ["", "RAW", "DIGEST"], index=0, key="verify-type")
    verify_grants = st.text_area("Grant tokens", value="", height=80, help="Optional JSON array", key="verify-grants")
    verify_auto = st.checkbox("Base64 encode message automatically", value=True, key="verify-auto")
    if st.button("Verify", key="do-verify"):
        if not verify_digest and not verify_message:
            st.error("Provide a message or message digest")
        else:
            try:
                grants = json.loads(verify_grants or "[]") if verify_grants else None
            except json.JSONDecodeError as exc:
                st.error(f"Invalid grant token JSON: {exc}")
            else:
                payload: Dict[str, object] = {
                    "signature": verify_signature,
                    "signing_algorithm": verify_algorithm,
                }
                if verify_key_id:
                    payload["key_id"] = verify_key_id
                if verify_digest:
                    payload["message_digest"] = verify_digest
                else:
                    payload["message"] = base64.b64encode(verify_message.encode()).decode() if verify_auto else verify_message
                if verify_type:
                    payload["message_type"] = verify_type
                if grants:
                    payload["grant_tokens"] = grants
                try:
                    st.json(_post("/kms/verify", payload))
                except Exception as exc:
                    st.error(f"Verify failed: {exc}")


# Layout: credentials at top, feature tabs below
_credentials_form()

encrypt_tab, data_key_tab, sign_tab = st.tabs([
    "Encrypt/Decrypt",
    "Data Key",
    "Sign/Verify",
])

with encrypt_tab:
    _tab_encrypt()

with data_key_tab:
    _tab_data_key()

with sign_tab:
    _tab_sign_verify()


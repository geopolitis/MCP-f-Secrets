"""Secrets, transit, and lease workflows."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state  # noqa: E402


st.title("Vault Operations")
st.caption("Interact with KV secrets, transit, database, SSH, and MCP tools")

auth_state = get_auth_state()


def _auth_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if auth_state.api_key:
        headers["X-API-Key"] = auth_state.api_key
    if auth_state.jwt:
        headers["Authorization"] = f"Bearer {auth_state.jwt}"
    return headers


secret_tab, transit_tab, db_tab, ssh_tab, mcp_tab = st.tabs([
    "Secrets",
    "Transit",
    "Database",
    "SSH",
    "MCP Tools",
])

with secret_tab:
    st.subheader("Read Secret")
    col1, col2 = st.columns([2, 1])
    with col1:
        secret_path = st.text_input("Path", placeholder="env/app/config")
        version = st.number_input("Version", min_value=0, step=1, help="0 = latest", value=0)
    with col2:
        read_btn = st.button("Fetch")
    secret_result = st.empty()
    if read_btn and secret_path:
        try:
            params = {"version": version} if version else None
            resp = httpx.get(
                f"{auth_state.host}/secrets/{secret_path}",
                headers=_auth_headers(),
                params=params,
                timeout=5.0,
            )
            resp.raise_for_status()
            secret_result.json(resp.json())
        except Exception as exc:
            secret_result.error(f"Read failed: {exc}")

    st.subheader("Write Secret")
    colw1, colw2 = st.columns([2, 1])
    with colw1:
        write_path = st.text_input("Target path", key="write_path")
    with colw2:
        write_btn = st.button("Save", key="write_btn")
    secret_body = st.text_area("JSON payload", value="{\n  \"example\": \"value\"\n}", height=150)
    write_result = st.empty()
    if write_btn and write_path:
        try:
            payload = json.loads(secret_body or "{}")
        except json.JSONDecodeError as exc:
            write_result.error(f"Invalid JSON: {exc}")
        else:
            try:
                resp = httpx.put(
                    f"{auth_state.host}/secrets/{write_path}",
                    headers=_auth_headers(),
                    json={"data": payload},
                    timeout=5.0,
                )
                resp.raise_for_status()
                write_result.success("Secret stored successfully.")
            except Exception as exc:
                write_result.error(f"Write failed: {exc}")

with transit_tab:
    st.subheader("Encrypt")
    colte1, colte2 = st.columns([2, 1])
    with colte1:
        transit_key = st.text_input("Transit key name")
        plaintext = st.text_area("Plaintext", height=120)
    with colte2:
        encrypt_btn = st.button("Encrypt")
    encrypt_result = st.empty()
    if encrypt_btn and transit_key:
        try:
            resp = httpx.post(
                f"{auth_state.host}/transit/encrypt",
                headers=_auth_headers(),
                json={"key": transit_key, "plaintext": plaintext},
                timeout=5.0,
            )
            resp.raise_for_status()
            encrypt_result.json(resp.json())
        except Exception as exc:
            encrypt_result.error(f"Encrypt failed: {exc}")

    st.subheader("Decrypt")
    ctxt = st.text_area("Ciphertext", height=120, key="ciphertext")
    decrypt_btn = st.button("Decrypt")
    decrypt_result = st.empty()
    if decrypt_btn and transit_key:
        try:
            resp = httpx.post(
                f"{auth_state.host}/transit/decrypt",
                headers=_auth_headers(),
                json={"key": transit_key, "ciphertext": ctxt},
                timeout=5.0,
            )
            resp.raise_for_status()
            decrypt_result.json(resp.json())
        except Exception as exc:
            decrypt_result.error(f"Decrypt failed: {exc}")

with db_tab:
    st.subheader("Issue DB credentials")
    role = st.text_input("DB role", key="db_role")
    if st.button("Issue creds") and role:
        try:
            resp = httpx.post(
                f"{auth_state.host}/db/creds/{role}",
                headers=_auth_headers(),
                timeout=5.0,
            )
            resp.raise_for_status()
            st.json(resp.json())
        except Exception as exc:
            st.error(f"Issue failed: {exc}")

    st.subheader("Renew DB lease")
    lease_id = st.text_input("Lease ID", key="db_lease_id")
    increment = st.number_input("Increment seconds", min_value=0, step=60, value=0)
    if st.button("Renew lease") and lease_id:
        payload = {"lease_id": lease_id}
        if increment:
            payload["increment"] = increment
        try:
            resp = httpx.post(
                f"{auth_state.host}/db/renew",
                headers=_auth_headers(),
                json=payload,
                timeout=5.0,
            )
            resp.raise_for_status()
            st.json(resp.json())
        except Exception as exc:
            st.error(f"Renew failed: {exc}")

    st.subheader("Revoke DB lease")
    revoke_lease = st.text_input("Lease ID to revoke", key="db_revoke")
    if st.button("Revoke lease") and revoke_lease:
        try:
            resp = httpx.post(
                f"{auth_state.host}/db/revoke",
                headers=_auth_headers(),
                json={"lease_id": revoke_lease},
                timeout=5.0,
            )
            resp.raise_for_status()
            st.success("Lease revoked")
        except Exception as exc:
            st.error(f"Revoke failed: {exc}")

with ssh_tab:
    st.subheader("SSH OTP")
    otp_role = st.text_input("Role", key="ssh_role")
    otp_ip = st.text_input("IP", key="ssh_ip")
    otp_user = st.text_input("Username", key="ssh_user")
    otp_port = st.number_input("Port", min_value=0, max_value=65535, value=22)
    if st.button("Generate OTP") and otp_role and otp_ip and otp_user:
        payload = {"role": otp_role, "ip": otp_ip, "username": otp_user}
        if otp_port:
            payload["port"] = otp_port
        try:
            resp = httpx.post(
                f"{auth_state.host}/ssh/otp",
                headers=_auth_headers(),
                json=payload,
                timeout=5.0,
            )
            resp.raise_for_status()
            st.json(resp.json())
        except Exception as exc:
            st.error(f"OTP failed: {exc}")

    st.subheader("SSH Sign")
    sign_role = st.text_input("Role", key="ssh_sign_role")
    public_key = st.text_area("Public key", height=120)
    valid_principals = st.text_input("Valid principals", key="ssh_valid_principals")
    cert_type = st.selectbox("Certificate type", ["user", "host"], index=0)
    ttl_text = st.text_input("TTL (e.g. 1h, 30m)", value="1h")
    if st.button("Sign key") and sign_role and public_key:
        payload = {
            "role": sign_role,
            "public_key": public_key,
            "cert_type": cert_type,
        }
        if valid_principals:
            payload["valid_principals"] = valid_principals
        if ttl_text:
            payload["ttl"] = ttl_text
        try:
            resp = httpx.post(
                f"{auth_state.host}/ssh/sign",
                headers=_auth_headers(),
                json=payload,
                timeout=5.0,
            )
            resp.raise_for_status()
            st.json(resp.json())
        except Exception as exc:
            st.error(f"Sign failed: {exc}")

with mcp_tab:
    st.subheader("Call MCP tool")
    tool_name = st.text_input("Tool name", value="kv.list")
    args_json = st.text_area("Arguments JSON", value="{\n  \"prefix\": \"\"\n}")
    if st.button("Call tool"):
        try:
            arguments = json.loads(args_json or "{}")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")
        else:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            try:
                resp = httpx.post(
                    f"{auth_state.host}/mcp/rpc",
                    headers={**_auth_headers(), "Content-Type": "application/json"},
                    json=payload,
                    timeout=10.0,
                )
                resp.raise_for_status()
                st.json(resp.json())
            except Exception as exc:
                st.error(f"MCP call failed: {exc}")

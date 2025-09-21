"""Admin page for managing credentials and agent policies."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state  # noqa: E402


st.title("Admin & Authentication")
st.caption("Validate connectivity and review authentication context")

auth_state = get_auth_state()

st.subheader("Connection Test")
st.write("Confirm the service is reachable with the configured credentials.")

col1, col2 = st.columns([1, 3])
with col1:
    run_check = st.button("Ping /healthz")

with col2:
    result_placeholder = st.empty()

if run_check:
    headers = {}
    if auth_state.api_key:
        headers["X-API-Key"] = auth_state.api_key
    if auth_state.jwt:
        headers["Authorization"] = f"Bearer {auth_state.jwt}"
    try:
        resp = httpx.get(f"{auth_state.host}/healthz", headers=headers, timeout=5.0)
        result_placeholder.json({
            "status_code": resp.status_code,
            "body": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
        })
    except Exception as exc:
        result_placeholder.error(f"Request failed: {exc}")

st.divider()

st.subheader("Credential Overview")
st.json({
    "host": auth_state.host,
    "api_key_present": bool(auth_state.api_key),
    "jwt_present": bool(auth_state.jwt),
    "use_mtls": auth_state.use_mtls,
})

st.info(
    "Add forms here for API key management, JWT issuance, or policy generation as you extend the admin surface."
)


"""Streamlit entry point for managing the FastMCP service."""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote

import streamlit as st

# Allow pages to import from ui/lib without packaging the module.
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state, update_auth_state  # noqa: E402
from lib.users import load_users, record_activity  # noqa: E402


st.set_page_config(
    page_title="FastMCP Admin",
    page_icon="🔐",
    layout="wide",
)

st.title("FastMCP Admin Console")
st.caption("Lightweight Streamlit UI for the Model Context Protocol bridge")

auth_state = get_auth_state()
users = load_users()
profile_options = ["Custom"] + [u.subject for u in users]
default_index = 0
if auth_state.selected_profile and auth_state.selected_profile in profile_options:
    default_index = profile_options.index(auth_state.selected_profile)

# Ensure sidebar widgets have session-backed buffers so secrets persist across reruns.
st.session_state.setdefault("api_key_buffer", auth_state.api_key or "")
st.session_state.setdefault("jwt_buffer", auth_state.jwt or "")

with st.sidebar:
    st.header("Connection")
    host = st.text_input("Service URL", value=auth_state.host, help="FastAPI base URL")
    profile_choice = st.selectbox("User profile", options=profile_options, index=default_index)

    if profile_choice != "Custom" and profile_choice != auth_state.selected_profile:
        selected_user = next((u for u in users if u.subject == profile_choice), None)
        if selected_user:
            update_auth_state(
                host=host,
                api_key=selected_user.api_key,
                jwt=selected_user.jwt,
                use_api_key=True if selected_user.api_key else auth_state.use_api_key,
                use_jwt=True if selected_user.jwt else auth_state.use_jwt,
                selected_profile=selected_user.subject,
            )
            st.session_state["api_key_buffer"] = selected_user.api_key or ""
            st.session_state["jwt_buffer"] = selected_user.jwt or ""
            record_activity(selected_user.subject)
            st.experimental_rerun()
    elif profile_choice == "Custom" and auth_state.selected_profile is not None:
        update_auth_state(selected_profile=None)
        st.session_state["api_key_buffer"] = auth_state.api_key or ""
        st.session_state["jwt_buffer"] = auth_state.jwt or ""
        st.experimental_rerun()

    auth_state = get_auth_state()

    st.subheader("Credentials")
    use_api_key = st.checkbox("Use API Key", value=auth_state.use_api_key, key="sidebar-use-api")
    if use_api_key:
        api_key = st.text_input("API Key", type="password", key="api_key_buffer")
        if st.session_state.get("api_key_buffer"):
            st.caption("API key stored (hidden for safety)")
    else:
        api_key = None

    use_jwt = st.checkbox("Use JWT", value=auth_state.use_jwt, key="sidebar-use-jwt")
    if use_jwt:
        jwt = st.text_input("JWT Token", type="password", key="jwt_buffer")
        if st.session_state.get("jwt_buffer"):
            st.caption("JWT stored (hidden for safety)")
    else:
        jwt = None

    use_mtls = st.checkbox("Use mTLS headers from reverse proxy", value=auth_state.use_mtls)

    if st.button("Save session", type="primary"):
        final_api_key = (api_key or st.session_state.get("api_key_buffer", "")).strip() if use_api_key else None
        final_jwt = (jwt or st.session_state.get("jwt_buffer", "")).strip() if use_jwt else None
        update_auth_state(
            host=host,
            api_key=final_api_key,
            jwt=final_jwt,
            use_mtls=use_mtls,
            use_api_key=use_api_key,
            use_jwt=use_jwt,
            selected_profile=auth_state.selected_profile if profile_choice != "Custom" else None,
        )
        st.success("Session updated.")

st.info(
    "Use the pages sidebar to access Admin & Authentication, Observability, and Vault operations."
)

st.subheader("Getting Started")
st.markdown(
    """
    1. Configure the connection in the sidebar.
    2. Visit **Admin & Authentication** to validate credentials and view active principals.
    3. Use **Observability** to inspect health, metrics, and logs.
    4. Head to **Vault Operations** for secrets, transit, and lease workflows.
    """
)

docs_base = auth_state.host.rstrip("/")
rpc_url = f"{docs_base}/mcp/rpc"
sse_url = f"{docs_base}/mcp/sse"
st.markdown(
    f"REST docs: [Swagger UI]({docs_base}/docs) • [ReDoc]({docs_base}/redoc) • [OpenAPI JSON]({docs_base}/openapi.json)"
)
st.markdown(
    f"MCP endpoints: `POST {rpc_url}` • SSE stream: [{sse_url}]({sse_url})"
)
inspector_url = (
    "https://inspector.modelcontextprotocol.io/?" +
    f"server={quote(rpc_url, safe='')}" +
    (f"&eventStream={quote(sse_url, safe='')}" if sse_url else "")
)
st.markdown(
    f"Open MCP Inspector: [Launch UI]({inspector_url}) — configure headers with your API key/JWT in the inspector before issuing calls."
)

snapshot = {
    "host": auth_state.host,
    "api_key_configured": bool(auth_state.api_key) and auth_state.use_api_key,
    "jwt_configured": bool(auth_state.jwt) and auth_state.use_jwt,
    "use_mtls": auth_state.use_mtls,
    "selected_profile": auth_state.selected_profile,
}

st.subheader("Session Snapshot")
st.json(snapshot)

if auth_state.selected_profile:
    selected = next((u for u in users if u.subject == auth_state.selected_profile), None)
    if selected:
        st.caption(
            f"Active profile `{selected.subject}` • Scopes: {', '.join(selected.scopes)}"
            + (f" • Last active: {selected.last_active}" if selected.last_active else "")
        )

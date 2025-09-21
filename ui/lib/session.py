"""Shared helpers for Streamlit session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

import streamlit as st


@dataclass
class AuthState:
    """Holds credentials used to call the MCP/API service."""

    host: str = "http://127.0.0.1:8089"
    api_key: Optional[str] = None
    jwt: Optional[str] = None
    use_mtls: bool = False
    use_api_key: bool = True
    use_jwt: bool = False
    selected_profile: Optional[str] = None
    cached_profiles: Dict[str, Dict[str, Optional[str]]] = field(default_factory=dict)
    use_api_key: bool = True
    use_jwt: bool = False


_STATE_KEY = "fastmcp_auth_state"


def get_auth_state() -> AuthState:
    """Return the cached AuthState, creating a default copy if necessary."""

    if _STATE_KEY not in st.session_state:
        st.session_state[_STATE_KEY] = AuthState()
    return st.session_state[_STATE_KEY]


def update_auth_state(**kwargs) -> None:
    """Update one or more fields on the AuthState dataclass."""

    state = get_auth_state()
    for key, value in kwargs.items():
        if hasattr(state, key):
            setattr(state, key, value)

"""Multi-user administration for API keys and subjects."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd

import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.users import (  # noqa: E402
    UserRecord,
    delete_user,
    generate_api_key,
    load_users,
    upsert_user,
)

st.title("Manage Subjects & Keys")
st.caption("Create, rotate, and retire user credentials")
rerun = getattr(st, "experimental_rerun", getattr(st, "rerun", None))


def _format_ts(value: Optional[str]) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return value


def _is_expired(value: Optional[str]) -> Optional[bool]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception:
        return None

users = load_users()

if users:
    st.subheader("Current users")
    filter_text = st.text_input("Filter by subject or scope", "")
    rows = []
    for u in users:
        expired_flag = _is_expired(u.jwt_expires_at)
        ttl_value = "-"
        if u.jwt:
            if u.jwt_ttl_seconds in (None, 0):
                ttl_value = "unbounded"
            else:
                ttl_value = str(u.jwt_ttl_seconds)
        rows.append(
            {
                "Subject": u.subject,
                "API Key": u.api_key,
                "Scopes": ", ".join(u.scopes),
                "Last Active": _format_ts(u.last_active),
                "JWT Created": _format_ts(u.jwt_created_at),
                "JWT Expires": _format_ts(u.jwt_expires_at),
                "JWT Status": "Expired" if expired_flag else "Active" if expired_flag is not None else "No JWT",
                "JWT TTL (seconds)": ttl_value,
                "Description": u.description,
            }
        )
    df = pd.DataFrame(rows)
    if filter_text:
        mask = (
            df["Subject"].str.contains(filter_text, case=False, na=False)
            |
            df["Scopes"].str.contains(filter_text, case=False, na=False)
        )
        df = df[mask]
    st.dataframe(
        df,
        hide_index=True,
        use_container_width=True,
    )
    st.caption("Select cells to copy; use the context menu or keyboard shortcuts to duplicate data.")
    st.download_button(
        "Download as CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="fastmcp_users.csv",
        mime="text/csv",
    )
else:
    st.info("No users registered yet. Create a new subject below.")

st.divider()

with st.expander("Create new user", expanded=False):
    new_subject = st.text_input("Subject", placeholder="agent_finance")
    default_scopes = ["read", "write", "delete", "list"]
    scopes_input = st.multiselect(
        "Scopes",
        options=sorted(set(default_scopes + [s for u in users for s in u.scopes])),
        default=default_scopes,
    )
    description = st.text_area("Description", help="Optional context for operators")
    want_jwt = st.checkbox("Generate JWT token", value=False, help="Requires JWT_HS256_SECRET env to be set")
    jwt_ttl = 0
    if want_jwt:
        jwt_ttl = int(st.number_input("JWT TTL seconds (0 = no expiry)", min_value=0, value=900, step=60))

    if st.button("Create user", key="create_user"):
        if not new_subject:
            st.error("Subject is required.")
        elif any(u.subject == new_subject for u in users):
            st.error("Subject already exists.")
        else:
            api_key = generate_api_key()
            jwt_token = None
            jwt_created_iso = None
            jwt_expires_iso = None
            if want_jwt:
                secret = os.environ.get("JWT_HS256_SECRET")
                if not secret:
                    st.warning("JWT_HS256_SECRET not set; skipping token generation.")
                else:
                    try:
                        created_ts = datetime.now(timezone.utc)
                        result = subprocess.run(
                            [
                                sys.executable,
                                "scripts/gen_jwt.py",
                                "--secret",
                                secret,
                                "--sub",
                                new_subject,
                                "--scopes",
                                ",".join(scopes_input),
                                *(["--ttl", str(jwt_ttl)] if jwt_ttl else []),
                            ],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                        jwt_token = result.stdout.strip()
                        jwt_created_iso = created_ts.isoformat()
                        jwt_expires_iso = (
                            (created_ts + timedelta(seconds=jwt_ttl)).isoformat()
                            if jwt_ttl
                            else None
                        )
                        st.success(
                            f"JWT created for `{new_subject}` (expires: { _format_ts(jwt_expires_iso) })"
                        )
                    except subprocess.CalledProcessError as exc:
                        st.error(f"Failed to generate JWT: {exc.stderr or exc.stdout}")
                        jwt_token = None
            ttl_value = jwt_ttl if want_jwt else None
            if want_jwt and not jwt_token:
                st.error("User not created because JWT could not be generated.")
                st.stop()
            record = UserRecord(
                subject=new_subject,
                api_key=api_key,
                scopes=list(scopes_input),
                description=description,
                jwt=jwt_token,
                jwt_created_at=jwt_created_iso,
                jwt_expires_at=jwt_expires_iso,
                jwt_ttl_seconds=ttl_value,
            )
            upsert_user(record)
            st.success(f"User `{new_subject}` created. API key copied below.")
            st.code(api_key, language="text")
            if jwt_token:
                st.code(jwt_token, language="text")
            st.info(
                "Apply policy: `python scripts/gen_policy.py --agent {subject} --mount \"${{KV_MOUNT:-secret}}\" --prefix \"${{DEFAULT_PREFIX:-mcp}}\" | vault policy write mcp-agent-{subject} -`".format(
                    subject=new_subject
                )
            )
            if rerun:
                rerun()

st.divider()

if users:
    subjects = [u.subject for u in users]
    selected = st.selectbox("Manage existing user", subjects)
    selected_user = next((u for u in users if u.subject == selected), None)
    if selected_user:
        st.subheader(f"Edit `{selected_user.subject}`")
        new_description = st.text_area("Description", value=selected_user.description or "")
        scope_edit = st.multiselect(
            "Scopes",
            options=sorted(set(["read", "write", "delete", "list"] + selected_user.scopes)),
            default=selected_user.scopes,
            key=f"scopes-{selected_user.subject}"
        )
        col_api, col_jwt = st.columns(2)
        with col_api:
            st.write("API Key")
            st.code(selected_user.api_key, language="text")
            if st.button("Regenerate API Key"):
                selected_user.api_key = generate_api_key()
                upsert_user(selected_user)
                st.success("API key rotated.")
                if rerun:
                    rerun()
        with col_jwt:
            st.write("JWT Token")
            if selected_user.jwt:
                st.code(selected_user.jwt, language="text")
                st.markdown(
                    f"Created: {_format_ts(selected_user.jwt_created_at)}  \
Expires: {_format_ts(selected_user.jwt_expires_at)}"
                )
                expired_flag = _is_expired(selected_user.jwt_expires_at)
                if expired_flag is not None:
                    st.caption("Status: " + ("🔴 Expired" if expired_flag else "🟢 Active"))
                else:
                    st.caption("Status: 🟢 Active (no expiry)")
                if selected_user.jwt_expires_at:
                    try:
                        exp_dt = datetime.fromisoformat(selected_user.jwt_expires_at)
                        if not exp_dt.tzinfo:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        remaining = exp_dt - datetime.now(timezone.utc)
                        if remaining.total_seconds() <= 0:
                            st.warning("JWT already expired.")
                        elif remaining <= timedelta(hours=24):
                            st.warning(f"JWT expires in {remaining}.")
                    except Exception:
                        pass
                st.caption(
                    "TTL: "
                    + (
                        f"{selected_user.jwt_ttl_seconds} seconds"
                        if selected_user.jwt_ttl_seconds not in (None, 0)
                        else "unbounded"
                    )
                )
            else:
                st.info("No JWT minted yet for this user.")
            jwt_ttl_existing = int(
                st.number_input(
                    "TTL seconds", min_value=0,
                    value=selected_user.jwt_ttl_seconds or 0,
                    step=60,
                    key=f"jwt-ttl-{selected_user.subject}"
                )
            )
            if st.button("Generate new JWT"):
                secret = os.environ.get("JWT_HS256_SECRET")
                if not secret:
                    st.error("Set JWT_HS256_SECRET before generating JWTs.")
                else:
                    try:
                        created_ts = datetime.now(timezone.utc)
                        result = subprocess.run(
                            [
                                sys.executable,
                                "scripts/gen_jwt.py",
                                "--secret",
                                secret,
                                "--sub",
                                selected_user.subject,
                                "--scopes",
                                ",".join(selected_user.scopes),
                                *(["--ttl", str(jwt_ttl_existing)] if jwt_ttl_existing else []),
                            ],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                        selected_user.jwt = result.stdout.strip()
                        selected_user.jwt_created_at = created_ts.isoformat()
                        selected_user.jwt_expires_at = (
                            (created_ts + timedelta(seconds=jwt_ttl_existing)).isoformat()
                            if jwt_ttl_existing
                            else None
                        )
                        selected_user.jwt_ttl_seconds = jwt_ttl_existing
                        upsert_user(selected_user)
                        st.success(
                            "JWT regenerated for `{}` (expires: {})".format(
                                selected_user.subject,
                                _format_ts(selected_user.jwt_expires_at),
                            )
                        )
                        if rerun:
                            rerun()
                    except subprocess.CalledProcessError as exc:
                        st.error(f"Failed to generate JWT: {exc.stderr or exc.stdout}")

        if st.button("Save changes"):
            scopes = scope_edit if scope_edit else selected_user.scopes
            selected_user.scopes = scopes
            selected_user.description = new_description
            upsert_user(selected_user)
            st.success("User updated.")
            if rerun:
                rerun()

        st.caption(
            "Last active: {last}".format(last=selected_user.last_active or "never")
        )

        st.warning("Deleting a user removes stored metadata only; revoke Vault tokens separately.")
        if st.button("Delete user", type="secondary"):
            delete_user(selected_user.subject)
            st.success("User removed.")
            if rerun:
                rerun()

st.divider()

st.subheader("Automation helpers")
commands = [
    "# Create policy file",
    "python scripts/gen_policy.py --agent <subject> --mount ${KV_MOUNT:-secret} --prefix ${DEFAULT_PREFIX:-mcp} > policy.hcl",
    "# Apply to Vault",
    "vault policy write mcp-agent-<subject> policy.hcl",
    "# Update API_KEYS_JSON (if using API key auth)",
    'export API_KEYS_JSON=\'{"<api-key>":"<subject>"}\'',
]
st.code("\n".join(commands), language="bash")

st.info(
    "See `scripts/manage_user.py` for CLI automation that updates `config/users.json` and generates credentials."
)

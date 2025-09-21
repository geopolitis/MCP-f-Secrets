"""Admin interface for managing AI agents."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state  # noqa: E402
from lib.users import UserRecord, load_users  # noqa: E402
from lib.agents import (  # noqa: E402
    AgentRecord,
    TaskRecord,
    add_task,
    delete_agent,
    generate_id,
    load_agents,
    remove_task,
    update_task_status,
    upsert_agent,
)

st.title("AI Agent Administration")
st.caption("Configure agents, credentials, and manage tasks")
rerun = getattr(st, "experimental_rerun", getattr(st, "rerun", None))

auth_state = get_auth_state()
base_url = auth_state.host.rstrip("/")
users = load_users()
user_lookup: Dict[str, UserRecord] = {u.subject: u for u in users}
user_subjects = list(user_lookup.keys())
agents = load_agents()

TASK_TEMPLATES: Dict[str, Dict] = {
    "kv_read": {"path": "configs/demo", "version": 0},
    "kv_write": {"path": "configs/demo", "data": {"example": "value"}},
    "http_request": {"method": "GET", "path": "/healthz", "params": None, "json": None},
    "mcp_tool": {"name": "kv.list", "arguments": {"prefix": ""}},
}
TASK_LABELS = {
    "kv_read": "KV Read",
    "kv_write": "KV Write",
    "http_request": "HTTP Request",
    "mcp_tool": "MCP Tool Call",
}
STATUS_CHOICES = ("pending", "in_progress", "completed", "failed")


def _agent_headers(agent: AgentRecord) -> Tuple[Dict[str, str], Optional[str]]:
    headers: Dict[str, str] = {}
    if agent.credential_mode == "linked":
        if not agent.credential_subject:
            return {}, "Linked user not specified"
        user = user_lookup.get(agent.credential_subject)
        if not user:
            return {}, f"Linked user `{agent.credential_subject}` not found"
        if user.api_key:
            headers["X-API-Key"] = user.api_key
        if user.jwt:
            headers["Authorization"] = f"Bearer {user.jwt}"
    elif agent.credential_mode == "api_key":
        if not agent.api_key:
            return {}, "API key missing"
        headers["X-API-Key"] = agent.api_key
    elif agent.credential_mode == "jwt":
        if not agent.jwt:
            return {}, "JWT missing"
        headers["Authorization"] = f"Bearer {agent.jwt}"
    return headers, None if headers else "No credentials available"


def _format_timestamp(ts: Optional[str]) -> str:
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ts


def _execute_task(agent: AgentRecord, task: TaskRecord) -> Tuple[bool, str]:
    headers, error = _agent_headers(agent)
    if error:
        return False, error

    action = task.action
    params = task.params or {}
    try:
        if action == "kv_read":
            path = params.get("path")
            if not path:
                return False, "`path` is required"
            version = params.get("version")
            resp = httpx.get(
                f"{base_url}/secrets/{path}",
                headers=headers,
                params={"version": version} if version else None,
                timeout=10.0,
            )
            resp.raise_for_status()
            return True, json.dumps(resp.json(), indent=2)
        if action == "kv_write":
            path = params.get("path")
            data = params.get("data")
            if not path or data is None:
                return False, "`path` and `data` required"
            resp = httpx.put(
                f"{base_url}/secrets/{path}",
                headers=headers,
                json={"data": data},
                timeout=10.0,
            )
            resp.raise_for_status()
            return True, "Secret written"
        if action == "http_request":
            method = (params.get("method") or "GET").upper()
            path = params.get("path") or "/healthz"
            req_json = params.get("json")
            req_params = params.get("params")
            resp = httpx.request(
                method,
                f"{base_url}{path}",
                headers=headers,
                json=req_json,
                params=req_params,
                timeout=10.0,
            )
            resp.raise_for_status()
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"text": resp.text}
            return True, json.dumps(body, indent=2)
        if action == "mcp_tool":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not name:
                return False, "Tool name required"
            payload = {
                "jsonrpc": "2.0",
                "id": generate_id("call"),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
            resp = httpx.post(
                f"{base_url}/mcp/rpc",
                headers={**headers, "Content-Type": "application/json"},
                json=payload,
                timeout=15.0,
            )
            resp.raise_for_status()
            return True, json.dumps(resp.json(), indent=2)
        return False, f"Unsupported task action: {action}"
    except httpx.HTTPStatusError as exc:
        return False, f"HTTP {exc.response.status_code}: {exc.response.text}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


# ---- overview table ----
rows: List[Dict[str, str]] = []
for agent in agents:
    status_counts = {status: 0 for status in STATUS_CHOICES}
    for task in agent.tasks:
        status_counts[task.status] = status_counts.get(task.status, 0) + 1
    rows.append(
        {
            "Name": agent.name,
            "Use LLM": "Yes" if agent.use_llm else "No",
            "LLM Provider": agent.llm_provider or "-",
            "Credential": agent.credential_subject if agent.credential_mode == "linked" else agent.credential_mode,
            "Tasks": str(len(agent.tasks)),
            "Completed": str(status_counts.get("completed", 0)),
            "In progress": str(status_counts.get("in_progress", 0)),
            "Pending": str(status_counts.get("pending", 0)),
            "Failed": str(status_counts.get("failed", 0)),
            "Updated": _format_timestamp(agent.updated_at),
        }
    )

df_agents = pd.DataFrame(rows)

# Organize functionality into dedicated tabs
(
    tab_overview,
    tab_import,
    tab_create,
    tab_manage,
) = st.tabs(["Overview", "Import", "Create", "Manage"])

with tab_overview:
    filter_text = st.text_input("Search agents", "", key="agent-search")
    df_view = df_agents.copy()
    if filter_text:
        mask = (
            df_view["Name"].str.contains(filter_text, case=False, na=False)
            |
            df_view["Credential"].str.contains(filter_text, case=False, na=False)
        )
        df_view = df_view[mask]
    st.dataframe(df_view, hide_index=True, use_container_width=True)
    st.download_button(
        "Download agents CSV",
        data=df_view.to_csv(index=False).encode("utf-8"),
        file_name="agents.csv",
        mime="text/csv",
    )

with tab_import:
    st.subheader("Import agent profiles")
    uploaded_agents = st.file_uploader(
        "Upload agent JSON (single record or list)",
        type="json",
        accept_multiple_files=False,
        key="agents-upload",
    )

    if uploaded_agents and st.button("Import uploaded agents", key="import-agents"):
        try:
            raw_bytes = uploaded_agents.getvalue()
            payload = raw_bytes.decode("utf-8") if raw_bytes else "[]"
            data = json.loads(payload or "[]")
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError("JSON must be an object or array of objects")
        except Exception as exc:
            st.error(f"Unable to parse JSON: {exc}")
        else:
            imported: List[str] = []
            for item in data:
                try:
                    record = AgentRecord.from_dict(item)
                except Exception as exc:  # pragma: no cover - defensive
                    st.warning(f"Skipping invalid record: {exc}")
                    continue
                if not record.name:
                    st.warning("Skipping record without a name")
                    continue
                upsert_agent(record)
                imported.append(record.name)
            if imported:
                st.success(f"Imported {len(imported)} agent(s): {', '.join(imported)}")
                if rerun:
                    rerun()
            else:
                st.warning("No valid agent records found in upload.")

with tab_create:
    st.subheader("Create new agent")
    new_name = st.text_input("Agent name", key="agent_name")
    new_description = st.text_area("Description", key="agent_description")
    use_llm = st.checkbox("Enable LLM", value=True, key="agent-use-llm")
    llm_provider = None
    llm_api_key = None
    if use_llm:
        llm_provider = st.selectbox("LLM provider", ["OpenAI", "Anthropic", "Custom"], index=0, key="agent-llm-provider")
        llm_api_key = st.text_input("LLM API key", type="password", key="agent-llm-key")

    cred_mode = st.radio("Credential source", ("Linked user", "API key", "JWT"), horizontal=True, key="agent-cred-mode")
    linked_subject = None
    api_key_value = None
    jwt_value = None
    if cred_mode == "Linked user":
        linked_subject = st.selectbox(
            "User subject",
            options=user_subjects or [""],
            index=0 if user_subjects else 0,
            key="agent-linked-subject",
        )
    elif cred_mode == "API key":
        api_key_value = st.text_input("API key", type="password", key="agent-api-key")
    else:
        jwt_value = st.text_area("JWT token", height=120, key="agent-jwt")

    if st.button("Create agent", key="create-agent"):
        if not new_name:
            st.error("Agent name is required.")
        elif any(a.name == new_name for a in agents):
            st.error("Agent already exists.")
        elif cred_mode == "Linked user" and not linked_subject:
            st.error("Select a user subject.")
        elif cred_mode == "API key" and not api_key_value:
            st.error("Provide an API key.")
        elif cred_mode == "JWT" and not jwt_value:
            st.error("Provide a JWT token.")
        elif use_llm and not llm_api_key:
            st.error("LLM API key required when LLM is enabled.")
        else:
            record = AgentRecord(
                name=new_name,
                description=new_description,
                use_llm=use_llm,
                llm_provider=llm_provider if use_llm else None,
                llm_api_key=llm_api_key if use_llm else None,
                credential_mode={"Linked user": "linked", "API key": "api_key", "JWT": "jwt"}[cred_mode],
                credential_subject=linked_subject if cred_mode == "Linked user" else None,
                api_key=api_key_value if cred_mode == "API key" else None,
                jwt=jwt_value if cred_mode == "JWT" else None,
            )
            upsert_agent(record)
            st.success(f"Agent `{new_name}` created.")
            if rerun:
                rerun()

with tab_manage:
    if not agents:
        st.info("Create an agent to begin configuration.")
    else:
        selected_name = st.selectbox("Manage existing agent", options=[a.name for a in agents], key="manage-select")
        agent = next((a for a in agents if a.name == selected_name), None)

        if agent:
            st.subheader(f"Manage `{agent.name}`")
            tab_details, tab_tasks, tab_danger = st.tabs(["Details", "Tasks", "Danger zone"])

            with tab_details:
                detail_cols = st.columns([2, 1])
                with detail_cols[0]:
                    with st.form(f"agent-details-{agent.name}"):
                        desc_edit = st.text_area("Description", value=agent.description or "", key=f"desc-{agent.name}")
                        llm_edit = st.checkbox("Enable LLM", value=agent.use_llm, key=f"llm-{agent.name}")
                        provider_options = ["OpenAI", "Anthropic", "Custom"]
                        default_provider_idx = (
                            provider_options.index(agent.llm_provider)
                            if agent.llm_provider in provider_options
                            else 0
                        )
                        llm_provider_edit = st.selectbox(
                            "LLM provider",
                            provider_options,
                            index=default_provider_idx,
                            key=f"llm-provider-{agent.name}",
                        )
                        llm_api_key_edit = st.text_input(
                            "LLM API key",
                            value=agent.llm_api_key or "",
                            type="password",
                            key=f"llm-key-{agent.name}",
                        )

                        cred_mode_edit = st.radio(
                            "Credential mode",
                            ("Linked user", "API key", "JWT"),
                            index={"linked": 0, "api_key": 1, "jwt": 2}[agent.credential_mode],
                            key=f"cred-mode-{agent.name}",
                        )
                        subject_edit = None
                        api_key_edit = None
                        jwt_edit = None
                        if cred_mode_edit == "Linked user":
                            subject_edit = st.selectbox(
                                "User subject",
                                options=user_subjects or [""],
                                index=user_subjects.index(agent.credential_subject) if agent.credential_subject in user_subjects else 0,
                                key=f"subject-{agent.name}"
                            )
                        elif cred_mode_edit == "API key":
                            api_key_edit = st.text_input("API key", value=agent.api_key or "", key=f"api-{agent.name}")
                        else:
                            jwt_edit = st.text_area("JWT token", value=agent.jwt or "", height=120, key=f"jwt-{agent.name}")

                        submitted = st.form_submit_button("Save changes")
                        if submitted:
                            if cred_mode_edit == "Linked user" and not subject_edit:
                                st.error("Select a user subject.")
                            elif cred_mode_edit == "API key" and not api_key_edit:
                                st.error("API key required.")
                            elif cred_mode_edit == "JWT" and not jwt_edit:
                                st.error("JWT token required.")
                            elif llm_edit and not llm_api_key_edit:
                                st.error("LLM API key required when LLM is enabled.")
                            else:
                                agent.description = desc_edit
                                agent.use_llm = llm_edit
                                agent.llm_provider = llm_provider_edit if llm_edit else None
                                agent.llm_api_key = llm_api_key_edit if llm_edit else None
                                agent.credential_mode = {"Linked user": "linked", "API key": "api_key", "JWT": "jwt"}[cred_mode_edit]
                                agent.credential_subject = subject_edit if cred_mode_edit == "Linked user" else None
                                agent.api_key = api_key_edit if cred_mode_edit == "API key" else None
                                agent.jwt = jwt_edit if cred_mode_edit == "JWT" else None
                                agent.updated_at = datetime.now(timezone.utc).isoformat()
                                upsert_agent(agent)
                                st.success("Agent updated.")
                                if rerun:
                                    rerun()

                with detail_cols[1]:
                    st.write("Credentials preview")
                    if agent.credential_mode == "linked":
                        st.info(f"Linked subject: {agent.credential_subject or 'n/a'}")
                    elif agent.credential_mode == "api_key":
                        st.code(agent.api_key or "-", language="text")
                    else:
                        st.code(agent.jwt or "-", language="text")
                    if agent.use_llm:
                        st.info(f"LLM provider: {agent.llm_provider or 'n/a'}")
                        if agent.llm_api_key:
                            st.code((agent.llm_api_key[:6] + "…"), language="text")
                        else:
                            st.warning("LLM enabled but no API key set.")

            with tab_tasks:
                task_upload = st.file_uploader(
                    "Upload task JSON for this agent",
                    type="json",
                    accept_multiple_files=False,
                    key=f"tasks-upload-{agent.name}",
                    help="Provide a JSON object or list defining task records to append."
                )
                if task_upload and st.button("Import tasks", key=f"import-tasks-{agent.name}"):
                    try:
                        content = task_upload.getvalue().decode("utf-8")
                        data = json.loads(content or "[]")
                        if isinstance(data, dict):
                            data = [data]
                        if not isinstance(data, list):
                            raise ValueError("JSON must be an object or array of objects")
                    except Exception as exc:
                        st.error(f"Unable to parse task JSON: {exc}")
                    else:
                        added = 0
                        for item in data:
                            if not isinstance(item, dict):
                                st.warning("Skipping non-object task entry")
                                continue
                            if not item.get("task_id"):
                                item = {**item, "task_id": generate_id("task")}
                            try:
                                task = TaskRecord.from_dict(item)
                            except Exception as exc:  # pragma: no cover - defensive
                                st.warning(f"Skipping invalid task entry: {exc}")
                                continue
                            agent.tasks.append(task)
                            added += 1
                        if added:
                            agent.updated_at = datetime.now(timezone.utc).isoformat()
                            upsert_agent(agent)
                            st.success(f"Imported {added} task(s) for `{agent.name}`.")
                            if rerun:
                                rerun()
                        else:
                            st.warning("No valid task records found in upload.")

                default_action = st.selectbox(
                    "Task type",
                    options=list(TASK_TEMPLATES.keys()),
                    format_func=lambda key: TASK_LABELS.get(key, key),
                    key=f"task-type-{agent.name}"
                )
                default_payload = json.dumps(TASK_TEMPLATES[default_action], indent=2)
                task_payload_text = st.text_area(
                    "Task params JSON",
                    value=default_payload,
                    key=f"task-params-{agent.name}"
                )
                task_notes = st.text_input("Initial notes", key=f"task-notes-{agent.name}")
                if st.button("Add task", key=f"add-task-{agent.name}"):
                    try:
                        params = json.loads(task_payload_text or "{}")
                    except json.JSONDecodeError as exc:
                        st.error(f"Invalid JSON: {exc}")
                    else:
                        task = add_task(agent, title=f"{TASK_LABELS.get(default_action, default_action)}", notes=task_notes, action=default_action, params=params)
                        upsert_agent(agent)
                        st.success(f"Task `{task.title}` added.")
                        if rerun:
                            rerun()

                if agent.tasks:
                    for task in agent.tasks:
                        with st.expander(f"{task.title} ({task.status})", expanded=False):
                            st.markdown(f"**Created:** {_format_timestamp(task.created_at)}  **Updated:** {_format_timestamp(task.updated_at)}")
                            st.markdown(f"**Action:** {task.action}")
                            st.code(json.dumps(task.params, indent=2), language="json")
                            st.text_area("Notes", value=task.notes, key=f"notes-{task.task_id}", disabled=True)

                            run_col, status_col, remove_col = st.columns([1, 2, 1])
                            with run_col:
                                if st.button("Run task", key=f"run-{task.task_id}"):
                                    task.status = "in_progress"
                                    task.updated_at = datetime.now(timezone.utc).isoformat()
                                    upsert_agent(agent)
                                    success, message = _execute_task(agent, task)
                                    task.status = "completed" if success else "failed"
                                    task.notes = message
                                    task.updated_at = datetime.now(timezone.utc).isoformat()
                                    upsert_agent(agent)
                                    st.success("Task completed" if success else "Task failed")
                                    if rerun:
                                        rerun()
                            with status_col:
                                new_status = st.selectbox(
                                    "Set status",
                                    STATUS_CHOICES,
                                    index=STATUS_CHOICES.index(task.status),
                                    key=f"status-{task.task_id}"
                                )
                                new_notes = st.text_input("Update notes", value=task.notes, key=f"edit-notes-{task.task_id}")
                                if st.button("Save status", key=f"save-status-{task.task_id}"):
                                    update_task_status(agent, task.task_id, new_status, new_notes)
                                    upsert_agent(agent)
                                    st.success("Task updated.")
                                    if rerun:
                                        rerun()
                            with remove_col:
                                if st.button("Remove task", key=f"remove-{task.task_id}"):
                                    remove_task(agent, task.task_id)
                                    upsert_agent(agent)
                                    st.warning("Task removed.")
                                    if rerun:
                                        rerun()
                else:
                    st.info("No tasks yet for this agent.")

            with tab_danger:
                st.markdown(f"**Selected agent:** `{agent.name}`")
                st.warning("Deleting an agent removes all of its tasks. This cannot be undone.")
                confirm_delete = st.checkbox("I understand and want to delete this agent", key=f"delete-confirm-{agent.name}")
                if st.button("Delete agent", key=f"delete-{agent.name}", disabled=not confirm_delete):
                    delete_agent(agent.name)
                    st.success("Agent deleted.")
                    if rerun:
                        rerun()

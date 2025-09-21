"""Admin interface for managing AI agents."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.users import load_users  # noqa: E402
from lib.agents import (  # noqa: E402
    AgentRecord,
    TaskRecord,
    add_task,
    delete_agent,
    generate_id,
    load_agents,
    remove_task,
    save_agents,
    update_task_status,
    upsert_agent,
)

st.title("AI Agent Administration")
st.caption("Configure agents, credentials, and manage tasks")
rerun = getattr(st, "experimental_rerun", getattr(st, "rerun", None))

users = load_users()
user_subjects = [u.subject for u in users]
agents = load_agents()

filter_text = st.text_input("Search agents", "")
rows = []
for agent in agents:
    task_counts: Dict[str, int] = {"pending": 0, "in_progress": 0, "completed": 0, "failed": 0}
    for task in agent.tasks:
        task_counts[task.status] = task_counts.get(task.status, 0) + 1
    rows.append(
        {
            "Name": agent.name,
            "Use LLM": "Yes" if agent.use_llm else "No",
            "Credential": agent.credential_subject if agent.credential_mode == "linked" else agent.credential_mode,
            "Tasks": len(agent.tasks),
            "Completed": task_counts.get("completed", 0),
            "In progress": task_counts.get("in_progress", 0),
            "Pending": task_counts.get("pending", 0),
            "Failed": task_counts.get("failed", 0),
            "Updated": agent.updated_at,
        }
    )

df_agents = pd.DataFrame(rows)
if filter_text:
    mask = (
        df_agents["Name"].str.contains(filter_text, case=False, na=False)
        |
        df_agents["Credential"].str.contains(filter_text, case=False, na=False)
    )
    df_agents = df_agents[mask]

st.dataframe(df_agents, hide_index=True, use_container_width=True)

st.download_button(
    "Download agents CSV",
    data=df_agents.to_csv(index=False).encode("utf-8"),
    file_name="agents.csv",
    mime="text/csv",
)

st.divider()

st.subheader("Create new agent")
new_name = st.text_input("Agent name", key="agent_name")
new_description = st.text_area("Description", key="agent_description")
use_llm = st.checkbox("Enable LLM", value=True)
cred_mode = st.radio("Credential source", ("Linked user", "API key", "JWT"), horizontal=True)
linked_subject = None
api_key_value = None
jwt_value = None
if cred_mode == "Linked user":
    linked_subject = st.selectbox("User subject", options=user_subjects or [""], index=0 if user_subjects else 0)
elif cred_mode == "API key":
    api_key_value = st.text_input("API key", type="password")
else:
    jwt_value = st.text_area("JWT token", height=120)

if st.button("Create agent"):
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
    else:
        record = AgentRecord(
            name=new_name,
            description=new_description,
            use_llm=use_llm,
            credential_mode={"Linked user": "linked", "API key": "api_key", "JWT": "jwt"}[cred_mode],
            credential_subject=linked_subject if cred_mode == "Linked user" else None,
            api_key=api_key_value if cred_mode == "API key" else None,
            jwt=jwt_value if cred_mode == "JWT" else None,
        )
        upsert_agent(record)
        st.success(f"Agent `{new_name}` created.")
        if rerun:
            rerun()

st.divider()

if agents:
    selected_name = st.selectbox("Manage existing agent", options=[a.name for a in agents])
    agent = next((a for a in agents if a.name == selected_name), None)
else:
    selected_name = None
    agent = None

if agent:
    st.subheader(f"Edit `{agent.name}`")
    col1, col2 = st.columns(2)
    with col1:
        desc_edit = st.text_area("Description", value=agent.description or "", key=f"desc-{agent.name}")
        llm_edit = st.checkbox("Enable LLM", value=agent.use_llm, key=f"llm-{agent.name}")
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

        if st.button("Save agent", key=f"save-{agent.name}"):
            if cred_mode_edit == "Linked user" and not subject_edit:
                st.error("Select a user subject.")
            elif cred_mode_edit == "API key" and not api_key_edit:
                st.error("API key required.")
            elif cred_mode_edit == "JWT" and not jwt_edit:
                st.error("JWT token required.")
            else:
                agent.description = desc_edit
                agent.use_llm = llm_edit
                agent.credential_mode = {"Linked user": "linked", "API key": "api_key", "JWT": "jwt"}[cred_mode_edit]
                agent.credential_subject = subject_edit if cred_mode_edit == "Linked user" else None
                agent.api_key = api_key_edit if cred_mode_edit == "API key" else None
                agent.jwt = jwt_edit if cred_mode_edit == "JWT" else None
                agent.updated_at = datetime.now(timezone.utc).isoformat()
                upsert_agent(agent)
                st.success("Agent updated.")
                if rerun:
                    rerun()

        if st.button("Delete agent", key=f"delete-{agent.name}"):
            delete_agent(agent.name)
            st.success("Agent deleted.")
            if rerun:
                rerun()

    with col2:
        st.write("Credentials preview")
        if agent.credential_mode == "linked":
            st.info(f"Linked subject: {agent.credential_subject or 'n/a'}")
        elif agent.credential_mode == "api_key":
            st.code(agent.api_key or "-", language="text")
        else:
            st.code(agent.jwt or "-", language="text")

    st.subheader("Tasks")
    new_task_title = st.text_input("Task title", key=f"task-title-{agent.name}")
    new_task_notes = st.text_area("Notes", key=f"task-notes-{agent.name}")
    if st.button("Add task", key=f"add-task-{agent.name}"):
        if not new_task_title:
            st.error("Task title required.")
        else:
            task = add_task(agent, new_task_title, new_task_notes)
            upsert_agent(agent)
            st.success(f"Task `{task.title}` added.")
            if rerun:
                rerun()

    if agent.tasks:
        for task in agent.tasks:
            with st.expander(f"{task.title} ({task.status})", expanded=False):
                st.markdown(f"**Created:** {task.created_at}  \
**Updated:** {task.updated_at}")
                st.text_area("Notes", value=task.notes, key=f"notes-{task.task_id}", disabled=True)
                new_status = st.selectbox(
                    "Status",
                    ("pending", "in_progress", "completed", "failed"),
                    index=("pending", "in_progress", "completed", "failed").index(task.status),
                    key=f"status-{task.task_id}"
                )
                edit_notes = st.text_input("Update notes", value=task.notes, key=f"edit-notes-{task.task_id}")
                if st.button("Update task", key=f"update-{task.task_id}"):
                    update_task_status(agent, task.task_id, new_status, edit_notes)
                    upsert_agent(agent)
                    st.success("Task updated.")
                    if rerun:
                        rerun()
                if st.button("Remove task", key=f"remove-{task.task_id}"):
                    remove_task(agent, task.task_id)
                    upsert_agent(agent)
                    st.warning("Task removed.")
                    if rerun:
                        rerun()
    else:
        st.info("No tasks yet for this agent.")

else:
    st.info("Create an agent to begin configuration.")

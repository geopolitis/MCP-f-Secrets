"""Utilities for managing AI agent configurations."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

AGENTS_FILE = Path(__file__).resolve().parents[1] / "config" / "agents.json"


@dataclass
class TaskRecord:
    task_id: str
    title: str
    status: str = "pending"  # pending, in_progress, completed, failed
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""
    action: str = "kv_read"
    params: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict) -> "TaskRecord":
        return cls(
            task_id=str(data.get("task_id")),
            title=str(data.get("title")),
            status=str(data.get("status", "pending")),
            created_at=str(data.get("created_at", datetime.now(timezone.utc).isoformat())),
            updated_at=str(data.get("updated_at", datetime.now(timezone.utc).isoformat())),
            notes=str(data.get("notes", "")),
            action=str(data.get("action", "kv_read")),
            params=dict(data.get("params", {})),
        )

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "notes": self.notes,
            "action": self.action,
            "params": self.params,
        }


@dataclass
class AgentRecord:
    name: str
    description: str = ""
    use_llm: bool = True
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    credential_mode: str = "linked"  # linked | api_key | jwt
    credential_subject: Optional[str] = None
    api_key: Optional[str] = None
    jwt: Optional[str] = None
    secrets_backend: str = "vault"  # vault | kms | hybrid
    tasks: List[TaskRecord] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_dict(cls, data: Dict) -> "AgentRecord":
        tasks_data = data.get("tasks") or []
        tasks = []
        for task in tasks_data:
            try:
                tasks.append(TaskRecord.from_dict(task))
            except Exception:
                continue
        return cls(
            name=str(data.get("name")),
            description=str(data.get("description", "")),
            use_llm=bool(data.get("use_llm", True)),
            llm_provider=data.get("llm_provider"),
            llm_api_key=data.get("llm_api_key"),
            credential_mode=str(data.get("credential_mode", "linked")),
            credential_subject=data.get("credential_subject"),
            api_key=data.get("api_key"),
            jwt=data.get("jwt"),
            secrets_backend=str(data.get("secrets_backend", "vault")),
            tasks=tasks,
            created_at=str(data.get("created_at", datetime.now(timezone.utc).isoformat())),
            updated_at=str(data.get("updated_at", datetime.now(timezone.utc).isoformat())),
        )

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "use_llm": self.use_llm,
            "llm_provider": self.llm_provider,
            "llm_api_key": self.llm_api_key,
            "credential_mode": self.credential_mode,
            "credential_subject": self.credential_subject,
            "api_key": self.api_key,
            "jwt": self.jwt,
            "secrets_backend": self.secrets_backend,
            "tasks": [task.to_dict() for task in self.tasks],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _ensure_file() -> None:
    AGENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not AGENTS_FILE.exists():
        AGENTS_FILE.write_text("[]", encoding="utf-8")


def load_agents() -> List[AgentRecord]:
    _ensure_file()
    raw = AGENTS_FILE.read_text(encoding="utf-8") or "[]"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = []
    agents: List[AgentRecord] = []
    for item in data or []:
        try:
            rec = AgentRecord.from_dict(item)
            if rec.name:
                agents.append(rec)
        except Exception:
            continue
    return agents


def save_agents(agents: List[AgentRecord]) -> None:
    _ensure_file()
    AGENTS_FILE.write_text(
        json.dumps([a.to_dict() for a in agents], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def upsert_agent(record: AgentRecord) -> None:
    agents = load_agents()
    for idx, existing in enumerate(agents):
        if existing.name == record.name:
            record.updated_at = datetime.now(timezone.utc).isoformat()
            agents[idx] = record
            break
    else:
        agents.append(record)
    save_agents(agents)


def delete_agent(name: str) -> None:
    agents = [a for a in load_agents() if a.name != name]
    save_agents(agents)


def generate_id(prefix: str = "task") -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def add_task(agent: AgentRecord, title: str, notes: str = "", action: str = "kv_read", params: Optional[Dict[str, Any]] = None) -> TaskRecord:
    task = TaskRecord(task_id=generate_id(), title=title, notes=notes, action=action, params=params or {})
    agent.tasks.append(task)
    agent.updated_at = datetime.now(timezone.utc).isoformat()
    return task


def update_task_status(agent: AgentRecord, task_id: str, status: str, notes: Optional[str] = None) -> None:
    for task in agent.tasks:
        if task.task_id == task_id:
            task.status = status
            if notes is not None:
                task.notes = notes
            task.updated_at = datetime.now(timezone.utc).isoformat()
            agent.updated_at = datetime.now(timezone.utc).isoformat()
            break


def remove_task(agent: AgentRecord, task_id: str) -> None:
    agent.tasks = [t for t in agent.tasks if t.task_id != task_id]
    agent.updated_at = datetime.now(timezone.utc).isoformat()

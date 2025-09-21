"""Utilities for managing multi-user metadata stored in JSON."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

USERS_FILE = Path(__file__).resolve().parents[1] / "config" / "users.json"


@dataclass
class UserRecord:
    subject: str
    api_key: str
    scopes: List[str] = field(default_factory=lambda: ["read", "write", "delete", "list"])
    description: str = ""
    last_active: Optional[str] = None
    jwt: Optional[str] = None
    jwt_created_at: Optional[str] = None
    jwt_expires_at: Optional[str] = None
    jwt_ttl_seconds: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict) -> "UserRecord":
        scopes = data.get("scopes") or []
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split(",") if s.strip()]
        return cls(
            subject=str(data.get("subject")),
            api_key=str(data.get("api_key")),
            scopes=list(scopes),
            description=str(data.get("description", "")),
            last_active=data.get("last_active"),
            jwt=data.get("jwt"),
            jwt_created_at=data.get("jwt_created_at"),
            jwt_expires_at=data.get("jwt_expires_at"),
            jwt_ttl_seconds=data.get("jwt_ttl_seconds"),
        )

    def to_dict(self) -> Dict:
        return {
            "subject": self.subject,
            "api_key": self.api_key,
            "scopes": self.scopes,
            "description": self.description,
            "last_active": self.last_active,
            "jwt": self.jwt,
            "jwt_created_at": self.jwt_created_at,
            "jwt_expires_at": self.jwt_expires_at,
            "jwt_ttl_seconds": self.jwt_ttl_seconds,
        }


def _ensure_file() -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text("[]", encoding="utf-8")


def load_users() -> List[UserRecord]:
    _ensure_file()
    raw = USERS_FILE.read_text(encoding="utf-8") or "[]"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = []
    users: List[UserRecord] = []
    for item in data or []:
        try:
            rec = UserRecord.from_dict(item)
            if rec.subject and rec.api_key:
                users.append(rec)
        except Exception:
            continue
    return users


def save_users(users: List[UserRecord]) -> None:
    USERS_FILE.write_text(
        json.dumps([u.to_dict() for u in users], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def generate_api_key(length: int = 32) -> str:
    # Generate a URL-safe token without padding characters for readability.
    return secrets.token_urlsafe(length)[: length]


def upsert_user(record: UserRecord) -> None:
    users = load_users()
    for idx, existing in enumerate(users):
        if existing.subject == record.subject:
            users[idx] = record
            break
    else:
        users.append(record)
    save_users(users)


def delete_user(subject: str) -> None:
    users = [u for u in load_users() if u.subject != subject]
    save_users(users)


def record_activity(subject: str) -> None:
    users = load_users()
    updated = False
    now = datetime.now(timezone.utc).isoformat()
    for user in users:
        if user.subject == subject:
            user.last_active = now
            updated = True
            break
    if updated:
        save_users(users)


def find_user(subject: str) -> Optional[UserRecord]:
    for user in load_users():
        if user.subject == subject:
            return user
    return None

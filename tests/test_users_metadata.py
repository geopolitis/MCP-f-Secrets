import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from ui.lib.users import UserRecord

def test_user_record_roundtrip(tmp_path, monkeypatch):
    record = UserRecord(
        subject="alice",
        api_key="key123",
        scopes=["read", "write"],
        description="example",
        last_active="2024-01-01T00:00:00+00:00",
        jwt="token",
        jwt_created_at="2024-01-01T00:00:00+00:00",
        jwt_expires_at="2024-01-02T00:00:00+00:00",
        jwt_ttl_seconds=3600,
    )
    data = record.to_dict()
    roundtrip = UserRecord.from_dict(json.loads(json.dumps(data)))
    assert roundtrip.jwt_created_at == "2024-01-01T00:00:00+00:00"
    assert roundtrip.jwt_ttl_seconds == 3600
    assert roundtrip.scopes == ["read", "write"]

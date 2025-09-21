import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from ui.lib.agents import AgentRecord, TaskRecord


def test_agent_record_roundtrip():
    task = TaskRecord(task_id="task-1", title="demo", status="pending")
    record = AgentRecord(
        name="agent-alpha",
        description="demo",
        use_llm=False,
        credential_mode="api_key",
        api_key="secret",
        tasks=[task],
    )
    data = record.to_dict()
    loaded = AgentRecord.from_dict(json.loads(json.dumps(data)))
    assert loaded.name == "agent-alpha"
    assert loaded.api_key == "secret"
    assert loaded.tasks[0].title == "demo"

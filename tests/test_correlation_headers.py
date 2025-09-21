import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))


def test_correlation_headers_present(client):
    resp = client.get("/healthz", headers={"X-API-Key": "dev-key"})
    assert resp.status_code == 200
    assert "X-Correlation-Id" in resp.headers
    trace_id = resp.headers.get("X-Trace-Id")
    assert trace_id is None or len(trace_id) == 32

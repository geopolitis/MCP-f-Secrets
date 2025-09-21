"""Observability dashboards for the FastMCP service."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Tuple

import httpx
import streamlit as st

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.append(str(APP_DIR))

from lib.session import get_auth_state  # noqa: E402


st.title("Observability")
st.caption("Monitor health, requests, and logs in near real time")

auth_state = get_auth_state()


def current_headers() -> Dict[str, str]:
    hdrs: Dict[str, str] = {}
    if auth_state.use_api_key and auth_state.api_key:
        hdrs["X-API-Key"] = auth_state.api_key
    if auth_state.use_jwt and auth_state.jwt:
        hdrs["Authorization"] = f"Bearer {auth_state.jwt}"
    return hdrs


def _cached_get(url: str, header_items: Tuple[Tuple[str, str], ...]) -> httpx.Response:
    resp = httpx.get(url, headers=dict(header_items), timeout=5.0)
    resp.raise_for_status()
    return resp


@st.cache_data(ttl=10)
def fetch_json(url: str, header_items: Tuple[Tuple[str, str], ...]):
    return _cached_get(url, header_items).json()


def parse_metrics(text: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {"in_flight": 0.0, "4xx": 0.0, "5xx": 0.0}
    for line in text.splitlines():
        if line.startswith("http_requests_in_progress") and not line.startswith("http_requests_in_progress_total"):
            try:
                metrics["in_flight"] = float(line.split(" ")[-1])
            except Exception:
                pass
        elif line.startswith("http_requests_total"):
            parts = line.split(" ")
            if len(parts) < 2:
                continue
            head = " ".join(parts[:-1])
            try:
                value = float(parts[-1])
            except Exception:
                continue
            if "status=" not in head:
                continue
            status_part = head.split("status=")[-1]
            status = status_part.split('"')[1] if '"' in status_part else status_part
            if status.startswith("4"):
                metrics["4xx"] += value
            elif status.startswith("5"):
                metrics["5xx"] += value
    return metrics


def render_missing_creds():
    st.warning("Configure API key or JWT in the sidebar to view restricted telemetry.")


headers_tuple = tuple(current_headers().items())
if not headers_tuple:
    render_missing_creds()
else:
    health_tab, metrics_tab, logs_tab = st.tabs(["Health", "Metrics", "Logs"])

    with health_tab:
        col1, col2, col3 = st.columns(3)
        try:
            api = fetch_json(f"{auth_state.host}/healthz", headers_tuple)
            col1.success("API healthy")
            col1.json(api)
        except Exception as exc:
            col1.error(f"API health failed: {exc}")

        try:
            vault = fetch_json(f"{auth_state.host}/readyz", headers_tuple)
            status = "ready" if vault.get("ok") else "not ready"
            getattr(col2, "success" if vault.get("ok") else "warning")(f"Vault {status}")
            col2.json(vault)
        except Exception as exc:
            col2.error(f"Vault readiness check failed: {exc}")

        try:
            summary = fetch_json(f"{auth_state.host}/observability/summary", headers_tuple)
            col3.metric("In-flight requests", summary.get("api", {}).get("in_flight", 0))
            col3.json(summary)
        except Exception as exc:
            col3.error(f"Summary lookup failed: {exc}")

    with metrics_tab:
        try:
            summary = fetch_json(f"{auth_state.host}/observability/summary", headers_tuple)
            block = summary.get("recent", {}) if isinstance(summary, dict) else {}
            s1, s2, s3 = st.columns(3)
            s1.metric("Recent entries", block.get("entries", 0))
            s2.metric("Recent 4xx", block.get("4xx", 0))
            s3.metric("Recent 5xx", block.get("5xx", 0))
        except Exception as exc:
            st.warning(f"Summary not available: {exc}")

        try:
            metrics_resp = _cached_get(f"{auth_state.host}/metrics", headers_tuple)
            parsed = parse_metrics(metrics_resp.text)
            m1, m2, m3 = st.columns(3)
            m1.metric("In-flight (current)", parsed.get("in_flight", 0))
            m2.metric("Total 4xx", int(parsed.get("4xx", 0)))
            m3.metric("Total 5xx", int(parsed.get("5xx", 0)))
            with st.expander("Raw metrics", expanded=False):
                st.code(metrics_resp.text[:6000], language="text")
        except Exception as exc:
            st.error(f"Metric scrape failed: {exc}")

    with logs_tab:
        st.write("Tail structured request logs (requires read scope)")
        limit = st.slider("Entries", min_value=10, max_value=200, value=50, step=10)
        log_type = st.selectbox("Log file", options=["requests", "responses", "server"])
        if st.button("Fetch logs"):
            try:
                resp = httpx.get(
                    f"{auth_state.host}/observability/logs/{log_type}",
                    headers=dict(headers_tuple),
                    params={"limit": limit},
                    timeout=5.0,
                )
                resp.raise_for_status()
                data = resp.json().get("entries", [])
                st.dataframe(data)
            except Exception as exc:
                st.error(f"Log fetch failed: {exc}")
        st.caption("Use the metrics tab to monitor 4xx/5xx spikes alongside these logs.")

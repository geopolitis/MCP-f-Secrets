import logging
import time
import json
import uuid
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import List

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from fastapi.middleware.cors import CORSMiddleware
import hvac
from .routes.kv import router as kv_router
from .routes.transit import router as transit_router
from .routes.health import router as health_router
from .routes.debug import router as debug_router
from .routes.db import router as db_router
from .routes.ssh import router as ssh_router
from .mcp_mount import mount_fastapi_mcp
from .routes.oauth_metadata import router as oauth_meta_router
from .mcp_rpc import router as mcp_rpc_router
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest, PROCESS_COLLECTOR, PLATFORM_COLLECTOR
from .settings import settings
from .security import require_scopes
from .vault import new_vault_client
from opentelemetry import trace


def _tail_json(path: Path, limit: int) -> List[dict]:
    if limit <= 0:
        return []
    if not path.exists() or not path.is_file():
        return []
    lines: List[str] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()[-limit:]
    except Exception:
        return []
    entries: List[dict] = []
    for raw in lines:
        try:
            entries.append(json.loads(raw))
        except Exception:
            entries.append({"raw": raw.strip()})
    return entries

def create_app() -> FastAPI:
    app = FastAPI(title="Vault MCP Bridge", version="0.2.0")
    req_logger = logging.getLogger("vault_mcp.request")
    resp_logger = logging.getLogger("vault_mcp.response")
    # Ensure logs directory exists
    logs_dir = Path(os.environ.get("LOG_DIR", "logs"))
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    class JSONFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            base = {
                "ts": time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(record.created)),
                "lvl": record.levelname.lower(),
                "msg": record.getMessage(),
                "logger": record.name,
            }
            extra = getattr(record, "extra", None)
            if isinstance(extra, dict):
                base.update(extra)
            return json.dumps(base, ensure_ascii=False)

    if not req_logger.handlers:
        h = logging.StreamHandler(); h.setFormatter(JSONFormatter()); req_logger.addHandler(h)
        try:
            fh = RotatingFileHandler(logs_dir / "requests.log", maxBytes=10_000_000, backupCount=5)
            fh.setFormatter(JSONFormatter()); req_logger.addHandler(fh)
        except Exception:
            pass
        lvl = os.environ.get("LOG_LEVEL", "info").upper()
        try:
            req_logger.setLevel(getattr(logging, lvl, logging.INFO))
        except Exception:
            req_logger.setLevel(logging.INFO)

    if not resp_logger.handlers:
        h2 = logging.StreamHandler(); h2.setFormatter(JSONFormatter()); resp_logger.addHandler(h2)
        try:
            fh2 = RotatingFileHandler(logs_dir / "responses.log", maxBytes=10_000_000, backupCount=5)
            fh2.setFormatter(JSONFormatter()); resp_logger.addHandler(fh2)
        except Exception:
            pass
        lvl = os.environ.get("LOG_LEVEL", "info").upper()
        try:
            resp_logger.setLevel(getattr(logging, lvl, logging.INFO))
        except Exception:
            resp_logger.setLevel(logging.INFO)

    try:
        uv_err = logging.getLogger("uvicorn.error")
        if not any(isinstance(h, RotatingFileHandler) for h in uv_err.handlers):
            ufh = RotatingFileHandler(logs_dir / "server.log", maxBytes=10_000_000, backupCount=5)
            ufh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            uv_err.addHandler(ufh)
    except Exception:
        pass

    # CORS (optional, for MCP Inspector over HTTP)
    try:
        from .settings import settings as _settings
        origins = (_settings.CORS_ALLOW_ORIGINS or "").strip()
        if origins:
            origin_list = [o.strip() for o in origins.split(",") if o.strip()]
            app.add_middleware(
                CORSMiddleware,
                allow_origins=origin_list,
                allow_methods=["GET", "POST", "OPTIONS"],
                allow_headers=["*"]
            )
    except Exception:
        pass

    # Prometheus
    registry = CollectorRegistry()
    try:
        registry.register(PROCESS_COLLECTOR)
        registry.register(PLATFORM_COLLECTOR)
    except Exception:
        pass
    http_req_hist = Histogram("http_request_duration_seconds", "Request duration", labelnames=("method", "route", "status"), registry=registry, buckets=(0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))
    http_req_count = Counter("http_requests_total", "Total HTTP requests", labelnames=("method", "route", "status"), registry=registry)
    http_req_in_flight = Gauge("http_requests_in_progress", "Number of HTTP requests actively being processed", registry=registry)
    correlation_counter = Counter("http_requests_with_correlation_total", "HTTP requests that carried/received correlation IDs", registry=registry)
    inflight_tracker = {"value": 0}

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.time(); request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        response: FastAPIResponse
        correlation_id = request.headers.get("x-correlation-id") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        try:
            http_req_in_flight.inc()
            inflight_tracker["value"] += 1
        except Exception:
            pass
        try:
            response = await call_next(request)
            return response
        finally:
            dur = time.time() - start
            route = request.scope.get("route").path if request.scope.get("route") else request.url.path
            try:
                status = getattr(locals().get('response', None), 'status_code', 500)
            except Exception:
                status = 500
            client_host = getattr(request.client, 'host', '-') if hasattr(request, 'client') else '-'
            try:
                http_req_hist.labels(request.method, route, str(status)).observe(dur)
                http_req_count.labels(request.method, route, str(status)).inc()
            except Exception:
                pass
            try:
                http_req_in_flight.dec()
                inflight_tracker["value"] = max(0, inflight_tracker["value"] - 1)
            except Exception:
                inflight_tracker["value"] = max(0, inflight_tracker["value"] - 1)
            try:
                response.headers["X-Correlation-Id"] = correlation_id
            except Exception:
                pass
            try:
                if 'response' in locals() and isinstance(response, FastAPIResponse):
                    response.headers["X-Request-Id"] = request_id
            except Exception:
                pass
            span = trace.get_current_span()
            trace_id_hex = None
            if span:
                ctx = span.get_span_context()
                if ctx and ctx.trace_id:
                    trace_id_hex = format(ctx.trace_id, "032x")
                    try:
                        response.headers["X-Trace-Id"] = trace_id_hex
                    except Exception:
                        pass
            if correlation_id:
                try:
                    correlation_counter.inc()
                except Exception:
                    pass
            req_logger.info(
                "request",
                extra={
                    "extra": {
                        "request_id": request_id,
                        "correlation_id": correlation_id,
                        "trace_id": trace_id_hex,
                        "client": client_host,
                        "method": request.method,
                        "path": route,
                        "status": status,
                        "duration_ms": int(dur*1000),
                    }
                },
            )

    @app.exception_handler(hvac.exceptions.InvalidPath)
    async def handle_vault_invalid_path(request: Request, exc: hvac.exceptions.InvalidPath):
        return JSONResponse(status_code=404, content={"detail": "Secret not found", "error": "invalid_path"})

    @app.exception_handler(hvac.exceptions.Forbidden)
    async def handle_vault_forbidden(request: Request, exc: hvac.exceptions.Forbidden):
        return JSONResponse(status_code=403, content={"detail": "Forbidden by Vault policy", "error": "forbidden"})

    @app.exception_handler(hvac.exceptions.VaultError)
    async def handle_vault_error(request: Request, exc: hvac.exceptions.VaultError):
        return JSONResponse(status_code=502, content={"detail": "Vault error", "error": "vault_error"})

    @app.get("/metrics")
    async def metrics():
        return FastAPIResponse(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    @app.get("/observability/summary")
    async def observability_summary():
        vault_status = {"ok": False}
        try:
            client = new_vault_client()
            vault_status = {"ok": bool(client.is_authenticated())}
        except hvac.exceptions.VaultError as exc:
            vault_status = {"ok": False, "detail": str(exc)}
        except Exception as exc:
            vault_status = {"ok": False, "detail": str(exc)}

        recent = _tail_json(logs_dir / "requests.log", 200)
        recent_4xx = 0
        recent_5xx = 0
        for entry in recent:
            status = str((entry or {}).get("status", ""))
            if status.startswith("4"):
                recent_4xx += 1
            elif status.startswith("5"):
                recent_5xx += 1

        return {
            "api": {"ok": True, "in_flight": inflight_tracker["value"]},
            "vault": vault_status,
            "mcp": {"ok": True},
            "recent": {
                "entries": len(recent),
                "4xx": recent_4xx,
                "5xx": recent_5xx,
            },
        }

    @app.get("/observability/logs/{log_type}")
    async def tail_logs(log_type: str, limit: int = 50, _: None = Depends(require_scopes(["read"]))):
        allowed = {
            "requests": logs_dir / "requests.log",
            "responses": logs_dir / "responses.log",
            "server": logs_dir / "server.log",
        }
        if log_type not in allowed:
            return JSONResponse(status_code=404, content={"detail": "unknown log"})
        limit = max(1, min(limit, 500))
        entries = _tail_json(allowed[log_type], limit)
        return {"log": log_type, "entries": entries}

    # Routers
    app.include_router(health_router)
    if settings.EXPOSE_REST_ROUTES:
        app.include_router(kv_router)
        app.include_router(transit_router)
        app.include_router(db_router)
        app.include_router(ssh_router)
        app.include_router(debug_router)
    # JSON-RPC MCP endpoints (HTTP transport)
    app.include_router(mcp_rpc_router)
    # OAuth metadata (discovery)
    app.include_router(oauth_meta_router)

    mount_fastapi_mcp(app)

    # OTel (optional)
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        service_name = os.environ.get("OTEL_SERVICE_NAME", "vault-mcp")
        resource = Resource(attributes={SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)
        if endpoint:
            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor().instrument_app(app)
    except Exception:
        pass
    return app

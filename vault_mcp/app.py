import logging
import time
import json
import uuid
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response as FastAPIResponse
import hvac
from .routes.kv import router as kv_router
from .routes.transit import router as transit_router
from .routes.health import router as health_router
from .routes.debug import router as debug_router
from .routes.db import router as db_router
from .routes.ssh import router as ssh_router
from .mcp_mount import mount_fastapi_mcp
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest, PROCESS_COLLECTOR, PLATFORM_COLLECTOR

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
        req_logger.setLevel(logging.INFO)

    if not resp_logger.handlers:
        h2 = logging.StreamHandler(); h2.setFormatter(JSONFormatter()); resp_logger.addHandler(h2)
        try:
            fh2 = RotatingFileHandler(logs_dir / "responses.log", maxBytes=10_000_000, backupCount=5)
            fh2.setFormatter(JSONFormatter()); resp_logger.addHandler(fh2)
        except Exception:
            pass
        resp_logger.setLevel(logging.INFO)

    try:
        uv_err = logging.getLogger("uvicorn.error")
        if not any(isinstance(h, RotatingFileHandler) for h in uv_err.handlers):
            ufh = RotatingFileHandler(logs_dir / "server.log", maxBytes=10_000_000, backupCount=5)
            ufh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            uv_err.addHandler(ufh)
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

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.time(); request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        response: FastAPIResponse
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
                if 'response' in locals() and isinstance(response, FastAPIResponse):
                    response.headers["X-Request-Id"] = request_id
            except Exception:
                pass
            req_logger.info("request", extra={"extra": {"request_id": request_id, "client": client_host, "method": request.method, "path": route, "status": status, "duration_ms": int(dur*1000)}})

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

    # Routers
    app.include_router(health_router)
    app.include_router(kv_router)
    app.include_router(transit_router)
    app.include_router(db_router)
    app.include_router(ssh_router)
    app.include_router(debug_router)

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

"""FastAPI application assembly: middleware, security headers, static dashboard.

Hardening:
  * Production startup REFUSES insecure critical configuration (fail-closed).
  * Demo seeding only when GX_SEED_DEMO_DATA=true; never auto-runs experiments.
  * OpenAPI/docs gated by environment (GX_ENABLE_DOCS overrides).
  * Strict CSP and security headers on every response (incl. 413/429).
  * Request-body limit enforced WHILE RECEIVING (covers chunked bodies).
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.routes import router
from app.config import get_settings
from app.observability.logging_setup import setup_logging

log = logging.getLogger("guardrailx.app")

MAX_BODY_BYTES = 1_048_576  # 1 MiB request cap (Phase 8)
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
       "form-action 'self'")


def _security_headers(response, settings) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = CSP
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"


def _reject(status: int, detail: str) -> JSONResponse:
    resp = JSONResponse({"detail": detail}, status_code=status)
    _security_headers(resp, get_settings())
    return resp


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    errors = settings.production_config_errors()
    if errors:
        raise RuntimeError("insecure production configuration: " + "; ".join(errors))
    # bootstrap identity-free foundation (policy + scenarios)
    from app.seed import bootstrap, ensure_demo_data, run_demo_experiment
    info = bootstrap()
    demo = ensure_demo_data(info)
    if demo:
        import asyncio
        asyncio.create_task(run_demo_experiment(demo))
        log.warning("demo data seeded (GX_SEED_DEMO_DATA=true) - never enable in production")
    if get_settings().environment == "production":
        log.warning("single-process deployment: run exactly ONE worker; in-memory rate "
                    "limiting and the SSE bus are not shared across workers (docs/OPERATIONS.md)")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)

    from app.db import migrate
    migrate()

    app_kwargs: dict = dict(
        title=settings.app_name, version="1.2.0",
        description="Universal AI guardrail research, bypass, and evaluation platform")
    if settings.docs_enabled:
        app_kwargs.update(docs_url="/api/docs", openapi_url="/api/openapi.json")
    else:
        app_kwargs.update(docs_url=None, openapi_url=None, redoc_url=None)
    app = FastAPI(lifespan=lifespan, **app_kwargs)
    app.include_router(router)

    # ------------------------------------------------------------ middleware
    rate_store: dict[str, deque] = defaultdict(deque)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        start = time.monotonic()
        client = request.client.host if request.client else "unknown"
        window = rate_store[client]
        now = time.monotonic()
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.rate_limit_per_minute and request.url.path.startswith("/api/"):
            return _reject(429, "rate limit exceeded")

        # Request-body limit (Phase 8): enforced while RECEIVING the body, so
        # chunked/streamed requests without Content-Length are also bounded.
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            return _reject(413, "request body too large")
        if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/api/"):
            body = b""
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BODY_BYTES:
                    return _reject(413, "request body too large")
            request._body = body  # noqa: SLF001 — cache the bounded body for downstream

        response = await call_next(request)
        _security_headers(response, settings)
        log.info("%s %s -> %s (%.0fms)", request.method, request.url.path,
                 response.status_code, (time.monotonic() - start) * 1000)
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"detail": "internal server error"}, status_code=500)

    # ---------------------------------------------------------------- static
    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(static_dir / "index.html"))

    return app


app = create_app()

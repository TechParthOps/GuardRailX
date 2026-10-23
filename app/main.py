"""FastAPI application assembly: middleware, security headers, static dashboard.

Hardening (Parts 6, 8, 9, 10):
  * Production startup REFUSES insecure critical configuration (fail-closed).
  * Demo seeding only when GX_SEED_DEMO_DATA=true; never auto-runs experiments
    otherwise.
  * OpenAPI/docs gated by environment (GX_ENABLE_DOCS overrides).
  * Strict Content-Security-Policy and additional security headers.
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

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
       "form-action 'self'")


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
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)

    from app.db import migrate
    migrate()

    app_kwargs: dict = dict(
        title=settings.app_name, version="1.1.0",
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
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        # request size guard (Part 6: oversized requests)
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > 1_048_576:
            return JSONResponse({"detail": "request body too large"}, status_code=413)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CSP
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
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

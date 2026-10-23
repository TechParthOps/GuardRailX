"""FastAPI application assembly: middleware, security headers, static dashboard."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from contextlib import asynccontextmanager

from app.api.v1.routes import router
from app.config import get_settings
from app.observability.logging_setup import setup_logging

log = logging.getLogger("guardrailx.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # bootstrap identity, default policy, scenario library, and labeled demo data
    from app.seed import bootstrap, run_demo_experiment
    info = bootstrap()
    if info.get("admin_created"):
        log.warning("initial admin created; password at data/initial_admin_password.txt "
                    "(GX_ADMIN_PASSWORD unset)")
    import asyncio
    asyncio.create_task(run_demo_experiment(info))
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)

    from app.db import migrate
    migrate()

    app = FastAPI(title=settings.app_name, version="1.0.0",
                  description="Universal AI guardrail research, bypass, and evaluation platform",
                  docs_url="/api/docs", openapi_url="/api/openapi.json",
                  lifespan=lifespan)
    app.include_router(router)

    # ------------------------------------------------------------ middleware
    rate_store: dict[str, deque] = defaultdict(deque)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        start = time.monotonic()
        # rate limit (per client IP; per-principal keys would need auth context here)
        client = request.client.host if request.client else "unknown"
        window = rate_store[client]
        now = time.monotonic()
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.rate_limit_per_minute and request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        window.append(now)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
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
    from pathlib import Path
    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(static_dir / "index.html"))

    return app


app = create_app()

"""SQLAlchemy engine/session setup and lightweight versioned migrations."""
from __future__ import annotations

import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

log = logging.getLogger("guardrailx.db")

engine = None
SessionLocal: sessionmaker | None = None


def init_engine() -> None:
    global engine, SessionLocal
    if engine is not None:
        return
    settings = get_settings()
    url = settings.resolved_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)
    if url.startswith("sqlite"):
        from sqlalchemy import event

        @event.listens_for(engine, "connect")
        def _sqlite_pragma(dbapi_conn, _rec):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def create_all() -> None:
    from app.models import Base
    init_engine()
    Base.metadata.create_all(bind=engine)


@contextmanager
def session_scope() -> Session:
    if SessionLocal is None:
        init_engine()
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def migrate() -> None:
    """Idempotent schema creation + version stamping.

    The full schema lives in app.models.Base.metadata (versioned code-first).
    Additional incremental migrations can be appended to MIGRATIONS below.
    """
    create_all()
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        ))
        inspector = inspect(engine)
        existing = {r[0] for r in conn.execute(text("SELECT version FROM schema_migrations"))}
        for version, fn in MIGRATIONS:
            if version not in existing:
                fn(conn, inspector)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (:v)"), {"v": version})
                log.info("applied migration", extra={"event_type": "migration", "object_id": str(version)})


MIGRATIONS: list[tuple[int, object]] = [
    # (1, lambda conn, inspector: conn.execute(text("ALTER TABLE ...")))
]


def reset_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None

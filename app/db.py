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


def _m1_rbac_isolation(conn, inspector) -> None:
    """v2 schema: credential scopes, email verification, project membership.

    Idempotent: applies only pieces missing from the inspected schema, so it
    works for both fresh installs (create_all already current) and existing
    v1.0 databases. Existing users are grandfathered as email-verified and
    existing credentials receive wildcard scopes (documented operator note).
    """
    def add_column_if_missing(table: str, ddl: str, column: str) -> None:
        cols = {c["name"] for c in inspector.get_columns(table)}
        if column not in cols:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))

    add_column_if_missing("users", "email_verified BOOLEAN DEFAULT 0", "email_verified")
    add_column_if_missing("auth_tokens", "scopes JSON DEFAULT '[\"*\"]'", "scopes")
    inspector.clear_cache()
    if not inspector.has_table("user_tokens"):
        conn.execute(text("""
            CREATE TABLE user_tokens (
                id VARCHAR(40) PRIMARY KEY,
                user_id VARCHAR(40) NOT NULL REFERENCES users(id),
                kind VARCHAR(24) NOT NULL,
                token_hash VARCHAR(128) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"""))
        conn.execute(text("CREATE INDEX ix_user_tokens_user_id ON user_tokens (user_id)"))
        conn.execute(text("CREATE INDEX ix_user_tokens_kind ON user_tokens (kind)"))
    if not inspector.has_table("project_members"):
        conn.execute(text("""
            CREATE TABLE project_members (
                id VARCHAR(40) PRIMARY KEY,
                project_id VARCHAR(40) NOT NULL REFERENCES projects(id),
                user_id VARCHAR(40) NOT NULL REFERENCES users(id),
                role VARCHAR(20) DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uq_project_member UNIQUE (project_id, user_id)
            )"""))
        conn.execute(text("CREATE INDEX ix_project_members_project_id ON project_members (project_id)"))
        conn.execute(text("CREATE INDEX ix_project_members_user_id ON project_members (user_id)"))
    # backfills (idempotent by construction)
    conn.execute(text("UPDATE auth_tokens SET scopes = '[\"*\"]' WHERE scopes IS NULL"))
    conn.execute(text("UPDATE users SET email_verified = 1 WHERE email_verified IS NULL"))
    conn.execute(text("""
        INSERT OR IGNORE INTO project_members (id, project_id, user_id, role)
        SELECT 'pm_' || substr(hex(randomblob(10)), 1, 16), p.id, p.owner_id, 'admin'
        FROM projects p
        WHERE NOT EXISTS (SELECT 1 FROM project_members m
                          WHERE m.project_id = p.id AND m.user_id = p.owner_id)
    """))


MIGRATIONS: list[tuple[int, object]] = [
    (1, _m1_rbac_isolation),
]


def reset_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None

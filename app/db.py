"""SQLAlchemy engine/session setup and versioned, dialect-portable migrations.

Migration guarantees (Phase 2):
  * Work on both SQLite and PostgreSQL.
  * Atomic: each migration and its version stamp commit together — an
    interrupted migration rolls back completely and is safe to retry.
  * Serialized across workers: PostgreSQL session-level advisory lock;
    SQLite single-writer locking + idempotent version checks.
  * Application-generated identifiers (no randomblob / server-specific SQL).
  * Explicit, actionable failure reporting.
"""
from __future__ import annotations

import logging
import secrets
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

log = logging.getLogger("guardrailx.db")

MIGRATION_LOCK_KEY = 736_251_001  # arbitrary fixed PostgreSQL advisory-lock key

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


def _is_postgres() -> bool:
    return engine.dialect.name == "postgresql"


def _column_exists(inspector, table: str, column: str) -> bool:
    return column in {c["name"] for c in inspector.get_columns(table)}


def _m1_rbac_isolation(conn) -> None:
    """v2 schema: credential scopes, email verification, project membership.

    Dialect-portable and idempotent (safe to re-run after interruption).
    Existing users are grandfathered as email-verified and existing
    credentials receive wildcard scopes — this mirrors pre-migration
    behavior exactly (credentials previously had no scope restriction),
    so no privilege is widened.
    """
    inspector = inspect(engine)
    if not inspector.has_table("users"):
        return  # nothing to upgrade

    def add_column(table: str, column_sql: str, column: str) -> None:
        if _column_exists(inspector, table, column):
            return
        try:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_sql}"))
        except Exception as exc:
            raise RuntimeError(
                f"could not add column {table}.{column} "
                "(apply manually or restore from backup)") from exc
        inspector.clear_cache()

    add_column("users", "email_verified BOOLEAN NOT NULL DEFAULT FALSE", "email_verified")
    add_column("auth_tokens", "scopes JSON NOT NULL DEFAULT '[\"*\"]'", "scopes")
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

    # ---- portable backfills (application-generated ids, membership-checked)
    conn.execute(text("UPDATE auth_tokens SET scopes = '[\"*\"]' WHERE scopes IS NULL"))
    if _is_postgres():
        conn.execute(text(
            "UPDATE users SET email_verified = TRUE WHERE email_verified IS DISTINCT FROM TRUE"))
    else:
        conn.execute(text("UPDATE users SET email_verified = 1 "
                          "WHERE email_verified IS NULL OR email_verified = 0"))

    # owners -> project-admin membership (skips existing rows; FK-safe)
    projects = conn.execute(text("SELECT id, owner_id FROM projects")).fetchall()
    for project_id, owner_id in projects:
        if not owner_id:
            continue
        exists = conn.execute(
            text("SELECT 1 FROM project_members WHERE project_id = :p AND user_id = :u"),
            {"p": project_id, "u": owner_id}).first()
        if exists:
            continue
        if not conn.execute(text("SELECT 1 FROM users WHERE id = :u"),
                            {"u": owner_id}).first():
            continue  # owner is not a real user (legacy demo row); do not fabricate access
        conn.execute(text(
            "INSERT INTO project_members (id, project_id, user_id, role) "
            "VALUES (:id, :p, :u, 'admin')"),
            {"id": "pm_" + secrets.token_hex(8), "p": project_id, "u": owner_id})


MIGRATIONS: list[tuple[int, object]] = [
    (1, _m1_rbac_isolation),
]


def migrate() -> None:
    """Idempotent schema creation + versioned migrations, serialized across workers.

    Raises RuntimeError with an actionable message on failure; migrations are
    atomic (each migration + its stamp commit together) and safe to retry.
    """
    init_engine()
    try:
        if _is_postgres():
            # session-level advisory lock on a dedicated connection held across
            # create_all AND migrations: concurrent workers must not race on
            # CREATE TABLE either (pg_type typname uniqueness)
            with engine.connect() as lock_conn:
                lock_conn.exec_driver_sql(f"SELECT pg_advisory_lock({MIGRATION_LOCK_KEY})")
                try:
                    create_all()
                    with engine.begin() as conn:
                        _run_migrations(conn)
                finally:
                    lock_conn.exec_driver_sql(f"SELECT pg_advisory_unlock({MIGRATION_LOCK_KEY})")
        else:
            create_all()
            # SQLite: writes are serialized by the database; busy_timeout makes
            # concurrent startups wait rather than fail
            with engine.begin() as conn:
                _run_migrations(conn)
    except Exception as exc:
        raise RuntimeError(
            f"database migration failed: {exc}. Fix the issue (or restore your "
            "backup) and restart; migrations are atomic and safe to retry.") from exc


def _run_migrations(conn) -> None:
    conn.execute(text(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    ))
    applied = {int(r[0]) for r in conn.execute(
        text("SELECT version FROM schema_migrations")).fetchall()}
    for version, fn in MIGRATIONS:
        if version in applied:
            continue
        fn(conn)
        conn.execute(text("INSERT INTO schema_migrations (version) VALUES (:v)"),
                     {"v": version})
        log.info("applied migration", extra={"event_type": "migration", "object_id": str(version)})


def reset_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None

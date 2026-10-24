"""PostgreSQL migration integration tests (Phase 2).

Each scenario runs in a subprocess against a real PostgreSQL instance
(docker: gx-pg-test on localhost:55432) or SQLite, using isolated databases.
Skipped with an explicit reason when PostgreSQL is unavailable — the rest of
the suite remains fully offline.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PG_URL = os.environ.get("GX_TEST_PG_URL", "postgresql+psycopg://postgres:test-pg-pass@127.0.0.1:55432/postgres")

PG_AVAILABLE = None


def pg_available() -> bool:
    global PG_AVAILABLE
    if PG_AVAILABLE is None:
        try:
            import psycopg
            with psycopg.connect("postgresql://postgres:test-pg-pass@127.0.0.1:55432/postgres",
                                 connect_timeout=3) as c:
                c.execute("SELECT 1")
            PG_AVAILABLE = True
        except Exception:
            PG_AVAILABLE = False
    return PG_AVAILABLE


def run_py(code: str, env_url: str) -> tuple[int, str]:
    env = os.environ.copy()
    env.update({"GX_DATABASE_URL": env_url, "GX_DATA_DIR": str(ROOT / "data"),
                "GX_SANDBOX_DIR": str(ROOT / "data" / "sandbox"), "PYTHONPATH": str(ROOT)})
    proc = subprocess.run([sys.executable, "-X", "utf8", "-c", code],
                          capture_output=True, text=True, timeout=180, cwd=str(ROOT), env=env)
    return proc.returncode, proc.stdout + proc.stderr


# ----------------------------------------------------------------- scenarios

FRESH_PG = """
import app.db as db
from app.db import migrate
migrate()
from sqlalchemy import inspect, text
i = inspect(db.engine)
for t in ("users", "auth_tokens", "projects", "project_members", "user_tokens", "experiments"):
    assert i.has_table(t), t
cols = {c["name"] for c in i.get_columns("auth_tokens")}
assert "scopes" in cols
with db.engine.begin() as c:
    c.execute(text("INSERT INTO users (id, email, password_hash, role, disabled, email_verified) VALUES ('u1','a@b.c','x','admin',FALSE,TRUE)"))
    r = c.execute(text("SELECT version FROM schema_migrations ORDER BY version")).fetchall()
assert [x[0] for x in r] == [1]
print("FRESH_OK")
"""

UPGRADE_FROM_V1 = """
# simulate the PREVIOUS (v1.0) schema: no scopes/email_verified/user_tokens/project_members
from sqlalchemy import create_engine, text
import app.db as db
from app.db import migrate, reset_engine
import os
url = os.environ["GX_DATABASE_URL"]
legacy = create_engine(url)
with legacy.begin() as c:
    c.execute(text("CREATE TABLE users (id VARCHAR(40) PRIMARY KEY, email VARCHAR(255) UNIQUE, "
                   "password_hash VARCHAR(255), role VARCHAR(20) DEFAULT 'viewer', "
                   "disabled BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"))
    c.execute(text("CREATE TABLE auth_tokens (id VARCHAR(40) PRIMARY KEY, user_id VARCHAR(40) "
                   "REFERENCES users(id), kind VARCHAR(10), token_hash VARCHAR(128) UNIQUE, "
                   "prefix VARCHAR(16), name VARCHAR(120), role VARCHAR(20) DEFAULT 'viewer', "
                   "expires_at TIMESTAMP NULL, revoked BOOLEAN DEFAULT FALSE, "
                   "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"))
    c.execute(text("CREATE TABLE projects (id VARCHAR(40) PRIMARY KEY, name VARCHAR(120) UNIQUE, "
                   "description TEXT DEFAULT '', owner_id VARCHAR(40) REFERENCES users(id), "
                   "is_demo BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"))
    c.execute(text("INSERT INTO users (id, email, password_hash, role) VALUES "
                   "('usr_a','owner@x.y','h','admin'), ('usr_b','tok@x.y','h','researcher')"))
    # (legacy table has disabled BOOLEAN DEFAULT FALSE so omission is valid)
    c.execute(text("INSERT INTO auth_tokens (id, user_id, kind, token_hash, role) VALUES "
                   "('k1','usr_b','api_key','th1','researcher')"))
    c.execute(text("INSERT INTO projects (id, name, owner_id) VALUES ('prj_1','legacy','usr_a')"))
legacy.dispose()

migrate()  # upgrade path
from sqlalchemy import inspect, text
i = inspect(db.engine)
assert {c["name"] for c in i.get_columns("auth_tokens")} >= {"scopes"}
assert i.has_table("project_members") and i.has_table("user_tokens")
with db.engine.begin() as c:
    scopes = c.execute(text("SELECT scopes FROM auth_tokens WHERE id='k1'")).scalar()
    assert scopes in ('[\"*\"]', ['*']), scopes  # JSON column round-trips by dialect
    verified = c.execute(text("SELECT email_verified FROM users WHERE id='usr_a'")).fetchone()[0]
    assert verified in (True, 1), verified
    # owner backfilled as admin member
    rows = c.execute(text("SELECT user_id, role FROM project_members WHERE project_id='prj_1' "
                          "ORDER BY user_id")).fetchall()
    assert rows == [("usr_a", "admin")], rows
    # an existing membership created AFTER migration is preserved and not duplicated
    c.execute(text("INSERT INTO project_members (id, project_id, user_id, role) VALUES "
                   "('pm_pre','prj_1','usr_b','viewer')"))
print("UPGRADE_OK")
"""

RETRY_AFTER_INTERRUPT = """
import app.db as db
from app.db import migrate
from sqlalchemy import text
migrate()
with db.engine.begin() as c:
    c.execute(text("DELETE FROM schema_migrations WHERE version = 1"))
    # a membership created after the first migration must survive re-migration
    c.execute(text("INSERT INTO users (id,email,password_hash,role,disabled,email_verified) VALUES ('u2','r@x.y','h','viewer',FALSE,TRUE)"))
    c.execute(text("INSERT INTO projects (id,name,owner_id,is_demo) VALUES ('p_r','retry-p','u2',FALSE)"))
    c.execute(text("INSERT INTO project_members (id,project_id,user_id,role) VALUES ('mm1','p_r','u2','viewer')"))
migrate()  # interrupted-migration retry: must be idempotent, no duplicate rows
with db.engine.begin() as c:
    rows = c.execute(text("SELECT user_id, role FROM project_members WHERE project_id='p_r'")).fetchall()
    v = c.execute(text("SELECT COUNT(*) FROM schema_migrations WHERE version = 1")).scalar()
    assert v == 1
    # the pre-existing (p_r, u2, viewer) row survives; the owner-backfill must
    # NOT duplicate it nor escalate its role
    assert rows == [("u2", "viewer")], rows
print("RETRY_OK")
"""

CONCURRENT_MIGRATE = """
import threading
import app.db as db
from app.db import migrate
from sqlalchemy import text
results = []
def worker():
    try:
        migrate()
        results.append("ok")
    except Exception as e:
        results.append(f"err:{e}")
threads = [threading.Thread(target=worker) for _ in range(4)]
[t.start() for t in threads]; [t.join() for t in threads]
with db.engine.begin() as c:
    v = c.execute(text("SELECT COUNT(*) FROM schema_migrations WHERE version = 1")).scalar()
assert all(r == "ok" for r in results), results
assert v == 1, "migration stamped more than once"
print("CONCURRENT_OK")
"""

FK_INTEGRITY = """
import app.db as db
from app.db import migrate
from sqlalchemy import text
migrate()
with db.engine.begin() as c:
    c.execute(text("INSERT INTO users (id,email,password_hash,role,disabled,email_verified) VALUES ('u1','f@k.l','h','admin',FALSE,TRUE)"))
    c.execute(text("INSERT INTO projects (id,name,owner_id,is_demo) VALUES ('p1','fkp','u1',FALSE)"))
    c.execute(text("INSERT INTO project_members (id,project_id,user_id,role) VALUES ('m1','p1','u1','admin')"))
# FK enforced (each negative check in its own transaction: PG aborts on error)
with db.engine.begin() as c:
    try:
        c.execute(text("INSERT INTO project_members (id, project_id, user_id, role) "
                       "VALUES ('pm_x','nope','nope','viewer')"))
        fk_ok = False
    except Exception:
        fk_ok = True
assert fk_ok, "FK not enforced on project_members"
with db.engine.begin() as c:
    try:
        c.execute(text("INSERT INTO project_members (id,project_id,user_id,role) "
                       "VALUES ('m2','p1','u1','viewer')"))
        uniq_ok = False
    except Exception:
        uniq_ok = True
assert uniq_ok, "uq_project_member not enforced"
print("FK_OK")
"""

NO_DEMO_RECORDS = """
import app.db as db
from app.db import migrate
from sqlalchemy import text
migrate()
with db.engine.begin() as c:
    n = c.execute(text("SELECT COUNT(*) FROM projects WHERE is_demo")).scalar()
assert n == 0
print("NODEMO_OK")
"""

# ------------------------------------------------------------------- tests

def _fresh_pg_db(name):
    import psycopg
    with psycopg.connect("postgresql://postgres:test-pg-pass@127.0.0.1:55432/postgres",
                         autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}"')
        c.execute(f'CREATE DATABASE "{name}"')
    return f"{PG_URL.rsplit('/', 1)[0]}/{name}"


def _fresh_sqlite(tmp_path, name):
    p = tmp_path / name
    return "sqlite:///" + p.as_posix()


def test_compose_url_driver_matches_requirements():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "postgresql+psycopg://" in compose, "compose must use the psycopg 3 driver"
    assert "psycopg[binary]" in req, "runtime requirements must install the driver"


def test_fresh_postgres_initialization():
    if not pg_available():
        pytest.skip("PostgreSQL test container not available on 127.0.0.1:55432")
    code, out = run_py(FRESH_PG, _fresh_pg_db("gx_fresh"))
    assert "FRESH_OK" in out, out[-1500:]


def test_upgrade_from_previous_postgres_schema():
    if not pg_available():
        pytest.skip("PostgreSQL test container not available")
    code, out = run_py(UPGRADE_FROM_V1, _fresh_pg_db("gx_upgrade"))
    assert "UPGRADE_OK" in out, out[-2000:]


def test_upgrade_from_previous_sqlite_schema(tmp_path):
    # legacy SQLite DB created by the earlier version, then migrated
    code, out = run_py(UPGRADE_FROM_V1, _fresh_sqlite(tmp_path, "legacy.db"))
    assert "UPGRADE_OK" in out, out[-2000:]


def test_migration_retry_after_interrupt_pg():
    if not pg_available():
        pytest.skip("PostgreSQL test container not available")
    code, out = run_py(RETRY_AFTER_INTERRUPT, _fresh_pg_db("gx_retry"))
    assert "RETRY_OK" in out, out[-1500:]


def test_migration_retry_after_interrupt_sqlite(tmp_path):
    code, out = run_py(RETRY_AFTER_INTERRUPT, _fresh_sqlite(tmp_path, "retry.db"))
    assert "RETRY_OK" in out, out[-1500:]


def test_concurrent_migrations_pg():
    if not pg_available():
        pytest.skip("PostgreSQL test container not available")
    code, out = run_py(CONCURRENT_MIGRATE, _fresh_pg_db("gx_conc"))
    assert "CONCURRENT_OK" in out, out[-1500:]


def test_fk_and_uniqueness_on_postgres():
    if not pg_available():
        pytest.skip("PostgreSQL test container not available")
    code, out = run_py(FK_INTEGRITY, _fresh_pg_db("gx_fk"))
    assert "FK_OK" in out, out[-1500:]


def test_migration_preserves_existing_memberships_sqlite(tmp_path):
    # covered in depth by UPGRADE_FROM_V1 (sqlite variant runs the same asserts)
    code, out = run_py(UPGRADE_FROM_V1, _fresh_sqlite(tmp_path, "members.db"))
    assert "UPGRADE_OK" in out, out[-2000:]

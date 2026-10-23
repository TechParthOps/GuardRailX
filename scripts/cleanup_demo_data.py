"""Demo-data cleanup utility (Part 9.2).

Removes demo resources identified by EXPLICIT markers (projects.is_demo and
the demo project's linked resources) — never by name or timestamp heuristics.

  python scripts/cleanup_demo_data.py --dry-run      # exact preview + counts
  python scripts/cleanup_demo_data.py --execute      # transactional cleanup
Options:
  --backup FILE   SQLite backup of the database before changes (recommended)
  --revoke-all-credentials  revoke every session/API key from the old deployment
  --reset-demo    remove the demo marker after cleanup (fresh install option)

Preserves: user accounts, user-created projects/resources, builtin scenarios,
default policy, audit history, schema.
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db import engine, session_scope  # noqa: E402
from app.models import (Approval, BenchmarkRun, Case, EventRecord,  # noqa: E402
                        Experiment, Finding, Project, Regression, Scenario, Target)


def demo_project_ids(s) -> list[str]:
    return [p.id for p in s.scalars(select(Project).where(Project.is_demo == True)).all()]  # noqa: E712


def collect(s) -> dict[str, list[str]]:
    """Exact records to delete, dependency-ordered."""
    pids = demo_project_ids(s)
    out: dict[str, list[str]] = {k: [] for k in
                                 ("projects", "targets", "experiments", "cases", "findings",
                                  "regressions", "approvals", "benchmarks", "events",
                                  "regression_scenarios")}
    if not pids:
        return out
    out["projects"] = pids
    out["targets"] = [t.id for t in s.scalars(select(Target).where(Target.project_id.in_(pids))).all()]
    exps = s.scalars(select(Experiment).where(Experiment.project_id.in_(pids))).all()
    out["experiments"] = [e.id for e in exps]
    exp_ids = [e.id for e in exps]
    if exp_ids:
        out["cases"] = [c.id for c in s.scalars(select(Case).where(Case.experiment_id.in_(exp_ids))).all()]
        out["findings"] = [f.id for f in s.scalars(select(Finding).where(Finding.experiment_id.in_(exp_ids))).all()]
        out["approvals"] = [a.id for a in s.scalars(select(Approval).where(Approval.experiment_id.in_(exp_ids))).all()]
        out["benchmarks"] = [b.id for b in s.scalars(select(BenchmarkRun).where(BenchmarkRun.experiment_id.in_(exp_ids))).all()]
        out["events"] = [e.id for e in s.scalars(select(EventRecord).where(EventRecord.experiment_id.in_(exp_ids))).all()]
        fids = out["findings"]
        if fids:
            out["regressions"] = [r.id for r in s.scalars(select(Regression).where(Regression.finding_id.in_(fids))).all()]
            out["regression_scenarios"] = [sc.key for sc in s.scalars(
                select(Scenario).where(Scenario.origin_finding_id.in_(fids))).all()]
    return out


def counts(s) -> dict[str, int]:
    return {
        "projects": s.query(Project).count(),
        "targets": s.query(Target).count(),
        "experiments": s.query(Experiment).count(),
        "findings": s.query(Finding).count(),
        "benchmarks": s.query(BenchmarkRun).count(),
        "events": s.query(EventRecord).count(),
        "builtin_scenarios": s.query(Scenario).filter(Scenario.source == "builtin").count(),
    }


def backup(db_path: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(dest))
    with dst:
        src.backup(dst)
    src.close()
    dst.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Remove demo data (explicit markers only)")
    ap.add_argument("--dry-run", action="store_true", help="preview deletions, change nothing")
    ap.add_argument("--execute", action="store_true", help="perform the cleanup")
    ap.add_argument("--backup", default="", help="backup DB to this file before changes")
    ap.add_argument("--revoke-all-credentials", action="store_true",
                    help="revoke ALL sessions and API keys (old deployment hygiene)")
    ap.add_argument("--reset-demo", action="store_true",
                    help="after cleanup, clear the demo marker so the platform starts clean")
    args = ap.parse_args()
    if not args.dry_run and not args.execute:
        ap.error("choose --dry-run or --execute")

    settings = get_settings()
    db_url = settings.resolved_database_url()
    print(f"database: {db_url}")

    with session_scope() as s:
        plan = collect(s)
        before = counts(s)
        total = sum(len(v) for v in plan.values())
        print("\nrecords to delete (dependency-ordered):")
        for k, ids in plan.items():
            print(f"  {k:22s} {len(ids):5d}" + (f"  e.g. {ids[:3]}" if ids else ""))
        print(f"  {'TOTAL':22s} {total:5d}")
        print("\ncounts before:", before)

        if args.dry_run:
            hint = " (add --backup <file> first)." if not args.backup else ""
            print("\nDRY RUN: no changes made. Re-run with --execute to apply" + hint)
            return 0

        if args.backup:
            if not db_url.startswith("sqlite"):
                print("--backup supports SQLite databases (use pg_dump for PostgreSQL)")
            else:
                db_path = Path(db_url.replace("sqlite:///", ""))
                backup(db_path, Path(args.backup))
                print(f"backup written: {args.backup}")

        # dependency-ordered deletion: children first, flushed per level
        # (models declare FK columns but no ORM relationships, so the unit of
        # work cannot infer ordering — explicit order + flush is required)
        def delete_bulk(model, column, ids) -> int:
            if not ids:
                return 0
            n = s.query(model).filter(column.in_(ids)).delete(synchronize_session=False)
            s.flush()
            return n

        deleted = 0
        deleted += delete_bulk(Scenario, Scenario.key, plan["regression_scenarios"])
        deleted += delete_bulk(Regression, Regression.id, plan["regressions"])
        deleted += delete_bulk(EventRecord, EventRecord.id, plan["events"])
        deleted += delete_bulk(BenchmarkRun, BenchmarkRun.id, plan["benchmarks"])
        deleted += delete_bulk(Approval, Approval.id, plan["approvals"])
        deleted += delete_bulk(Finding, Finding.id, plan["findings"])
        deleted += delete_bulk(Case, Case.id, plan["cases"])
        deleted += delete_bulk(Experiment, Experiment.id, plan["experiments"])
        deleted += delete_bulk(Target, Target.id, plan["targets"])
        deleted += delete_bulk(Project, Project.id, plan["projects"])
        print(f"deleted records: {deleted}")

        if args.revoke_all_credentials:
            from app.models import AuthToken
            n = s.query(AuthToken).filter(AuthToken.revoked == False).update({AuthToken.revoked: True})  # noqa: E712
            print(f"revoked credentials: {n}")

        if args.reset_demo:
            for p in s.scalars(select(Project).where(Project.is_demo == True)).all():  # noqa: E712
                p.is_demo = False

    with session_scope() as s:
        after = counts(s)
        print("counts after: ", after)
        remaining_demo = demo_project_ids(s)
        print("remaining demo projects:", len(remaining_demo))
        print("\nrecovery: restore the --backup file over the database file, then restart the app.")
        print("next: restart the application; sessions were revoked if requested;")
        print("      delete stale artifacts: data/initial_admin_password.txt, *.pid")
        return 0


if __name__ == "__main__":
    sys.exit(main())

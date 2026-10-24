"""Clean release packaging (Phase 12).

Builds a ZIP from the git-tracked tree (git archive) and VERIFIES the archive
contains no runtime artifacts. Exclusions are enforced by .gitignore; the
verification below proves the produced artifact, not merely the ignore rules.

Usage:  python scripts/make_release.py [-o guardrailx-release.zip]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PATTERNS = [
    "__pycache__", ".pyc", ".pytest_cache", ".git/",
    ".db", "-wal", "-shm", ".pid", "secret_key",
    "initial_admin_password", "pre_cleanup_backup",
    "sandbox/", ".coverage",
]

FORBIDDEN_EXACT_NAMES = {".env", ".gitignore.bak"}

REQUIRED_PATHS = [
    "app/main.py", "app/db.py", "app/models.py", "app/setup.py", "app/seed.py",
    "app/adapters/netguard.py", "app/adapters/pinned.py", "app/mailer.py",
    "app/auth/service.py", "app/api/v1/routes.py",
    "static/app.js", "static/index.html", "static/styles.css",
    "requirements.txt", "requirements-dev.txt", ".env.example",
    "docker-compose.yml", "Dockerfile", "README.md", "run.ps1",
    "scripts/cleanup_demo_data.py",
    "docs/OPERATIONS.md", "docs/SECURITY_AUDIT_REPORT.md", "docs/TEST_REPORT.md",
    "docs/REMEDIATION_CHECKLIST.md", "docs/ISSUE_REGISTER.md",
    "docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md", "docs/API.md",
    "docs/ADAPTER_GUIDE.md", "docs/SCENARIO_GUIDE.md", "docs/DATA_MODEL.md",
    "docs/SECURITY_LIMITATIONS.md", "docs/SAMPLE_REPORT.md",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default=str(ROOT / "dist" / "guardrailx-release.zip"))
    args = ap.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    # ensure clean commit state awareness
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=str(ROOT),
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        print(f"NOTE: working tree has {len(dirty.splitlines())} uncommitted change(s); "
              "the archive contains the last COMMIT plus uncommitted files via "
              "'git stash create' is not used — commit first for a reproducible build.")

    subprocess.run(["git", "archive", "--format=zip", "--output", str(out), "HEAD"],
                   cwd=str(ROOT), check=True)

    problems: list[str] = []
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        for name in names:
            low = name.lower()
            base = low.rsplit("/", 1)[-1]
            if base in FORBIDDEN_EXACT_NAMES:
                problems.append(f"forbidden artifact in archive: {name}")
            for pat in FORBIDDEN_PATTERNS:
                if pat in low:
                    problems.append(f"forbidden artifact in archive: {name} (pattern {pat})")
        for req in REQUIRED_PATHS:
            if not any(n == req for n in names):
                problems.append(f"required file missing from archive: {req}")
        # .env.example must not contain real-looking secrets
        env_example = next((n for n in names if n.endswith(".env.example")), None)
        if env_example:
            content = z.read(env_example).decode("utf-8", errors="replace")
            for line in content.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, _, val = line.partition("=")
                    if key.strip() in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GX_SECRET_KEY",
                                       "GX_PG_PASSWORD", "GX_SETUP_TOKEN") and val.strip():
                        problems.append(f".env.example contains a value for {key.strip()}")

    print(f"archive: {out}")
    print(f"entries: {len(names)}")
    if problems:
        print("\nPACKAGING VERIFICATION FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("packaging verification: PASS (no forbidden artifacts, all required files present, "
          ".env.example free of secret values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

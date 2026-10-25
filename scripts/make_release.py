"""Release packaging for GuardrailX (Priority 1).

Builds a SOURCE-ONLY release archive from a committed Git revision:
  * refuses an uncommitted/dirty tree unless --allow-dirty is passed
    (and then clearly labels the archive as unreviewed);
  * packages a deterministic revision (default: HEAD, or a tag/commit via --ref);
  * produces ONE clean top-level directory (guardrailx-<version>/);
  * excludes prohibited artifacts and verifies the result;
  * emits a SHA-256 checksum file.

The archive is source-only: it is NOT a deployable bundle (no baked
configuration, no database, no secrets). Deploy per README.md.

Usage:
  python scripts/make_release.py                      # from HEAD, verified
  python scripts/make_release.py --ref v1.0.0        # from a tag
  python scripts/make_release.py --allow-dirty       # explicit unreviewed build
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PATTERNS = [
    "__pycache__", ".pyc", ".pytest_cache", ".git/",
    ".db", "-wal", "-shm", ".pid", "secret_key",
    "initial_admin_password", "pre_cleanup_backup",
    "sandbox/", ".coverage", ".zip", "dist/",
]

FORBIDDEN_EXACT_NAMES = {".env", ".gitignore.bak"}

REQUIRED_PATHS = [
    "app/main.py", "app/db.py", "app/models.py", "app/setup.py", "app/seed.py",
    "app/mailer.py",
    "app/adapters/netguard.py", "app/adapters/pinned.py",
    "app/auth/service.py", "app/api/v1/routes.py",
    "static/app.js", "static/index.html", "static/styles.css",
    "requirements.txt", "requirements-dev.txt", ".env.example",
    "docker-compose.yml", "Dockerfile", "README.md", "LICENSE", "run.ps1",
    "scripts/cleanup_demo_data.py",
    "docs/OPERATIONS.md", "docs/SECURITY_AUDIT_REPORT.md", "docs/TEST_REPORT.md",
    "docs/REMEDIATION_CHECKLIST.md", "docs/ISSUE_REGISTER.md",
    "docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md", "docs/API.md",
    "docs/ADAPTER_GUIDE.md", "docs/SCENARIO_GUIDE.md", "docs/DATA_MODEL.md",
    "docs/SECURITY_LIMITATIONS.md", "docs/SAMPLE_REPORT.md",
    "CONTRIBUTING.md", "SECURITY.md", ".github/workflows/ci.yml",
]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True,
                          text=True, check=True).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a verified source release archive")
    ap.add_argument("--ref", default="HEAD", help="commit/tag to package (default: HEAD)")
    ap.add_argument("-o", "--output", default="")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="explicitly package an unreviewed working tree (discouraged)")
    args = ap.parse_args()

    # ---- 1. deterministic source revision --------------------------------
    commit = _git("rev-parse", args.ref)
    branch = _git("branch", "--show-current") or "(detached)"
    print(f"packaging ref={args.ref} commit={commit[:12]} branch={branch}")

    # ---- 2. dirty-tree safety --------------------------------------------
    status = _git("status", "--porcelain")
    dirty = bool(status)
    if dirty and not args.allow_dirty:
        print("REFUSING: working tree has uncommitted changes "
              f"({len(status.splitlines())} paths). The archive must represent the "
              "committed revision.\nCommit your changes first, or pass --allow-dirty "
              "to build an explicitly-unreviewed archive.")
        return 2
    if dirty:
        print("WARNING: --allow-dirty: archive does NOT represent a committed, "
              "reviewed revision.")

    # ---- 3. build with a single top-level directory -----------------------
    try:
        version = _git("describe", "--tags", "--abbrev=0")
    except subprocess.CalledProcessError:
        version = "v0.0.0-dev"
    top = f"guardrailx-{version.lstrip('v')}/"
    out = Path(args.output) if args.output else ROOT / "dist" / f"guardrailx-{version.lstrip('v')}-source.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "archive", "--format=zip", f"--prefix={top}",
                    "--output", str(out), commit],
                   cwd=str(ROOT), check=True)

    # ---- 4. verify the archive -------------------------------------------
    problems: list[str] = []
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        stripped = [n[len(top):] for n in names if n.startswith(top)]
        for name in stripped:
            low = name.lower()
            base = low.rsplit("/", 1)[-1]
            if base in FORBIDDEN_EXACT_NAMES:
                problems.append(f"forbidden artifact: {name}")
            for pat in FORBIDDEN_PATTERNS:
                if pat in low:
                    problems.append(f"forbidden artifact: {name} (pattern {pat})")
        for req in REQUIRED_PATHS:
            if not any(n == req for n in stripped):
                problems.append(f"required file missing: {req}")
        # no nested archives / self-inclusion
        if any(n.lower().endswith(".zip") for n in stripped):
            problems.append("archive contains a nested archive")
        # sanitized env template
        env_name = next((n for n in stripped if n == ".env.example"), None)
        if env_name:
            content = z.read(top + env_name).decode("utf-8", errors="replace")
            for line in content.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, _, val = line.partition("=")
                    if key.strip() in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                                       "GX_SECRET_KEY", "GX_PG_PASSWORD",
                                       "GX_SETUP_TOKEN", "SMTP_PASSWORD",
                                       "GX_SMTP_PASSWORD") and val.strip():
                        problems.append(f".env.example contains a value for {key.strip()}")

    if problems:
        print("\nPACKAGING VERIFICATION FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1

    # ---- 5. SHA-256 checksum ----------------------------------------------
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    checksum_file = out.with_suffix(out.suffix + ".sha256")
    checksum_file.write_text(f"{digest}  {out.name}\n", encoding="utf-8")

    print(f"archive:   {out.name}  ({len(names)} entries, top-level: {top})")
    print(f"source:    {'COMMITTED (clean tree)' if not dirty else 'UNCOMMITTED (--allow-dirty)'}")
    print(f"sha256:    {digest}")
    print(f"checksum:  {checksum_file.name}")
    print("type:      source-only (deploy per README.md)")
    print("verification: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

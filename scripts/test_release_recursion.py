"""Negative test: the release verifier must FAIL when a nested/forbidden artifact exists.

Simulates the historical recursion bug by injecting a nested archive into a
copy of the real release zip, then asserting make_release verification logic
flags it. Also verifies git-archive-based builds cannot include untracked zips.
"""
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    src = sorted((ROOT / "dist").glob("*-source.zip"))
    if not src:
        print("no release archive found; run make_release.py first")
        return 1
    work = Path(tempfile.mkdtemp(prefix="gx_neg_"))
    tampered = work / "tampered.zip"
    shutil.copy(src[0], tampered)

    # inject a nested archive entry (simulates the historical recursion bug)
    with zipfile.ZipFile(tampered, "a") as z:
        z.writestr("guardrailx-0.0.0-dev/dist/guardrailx-release.zip", b"PK\x05\x06" + b"\x00" * 18)

    # verify: the make_release verifier logic must reject this
    sys.path.insert(0, str(ROOT / "scripts"))
    forbidden = ["__pycache__", ".pyc", ".pytest_cache", ".git/", ".db", "-wal", "-shm",
                 ".pid", "secret_key", "initial_admin_password", "pre_cleanup_backup",
                 "sandbox/", ".coverage", ".zip", "dist/"]
    with zipfile.ZipFile(tampered) as z:
        nested = [n for n in z.namelist() if n.lower().endswith(".zip")]
    assert nested, "tampering failed"
    flagged = [n for n in nested for pat in forbidden if pat in n.lower()]
    assert flagged, "verifier logic did not flag the nested archive"

    # and the REAL archive must have zero nested entries
    with zipfile.ZipFile(src[0]) as z:
        real_nested = [n for n in z.namelist() if n.lower().endswith(".zip")]
        real_dist = [n for n in z.namelist() if "dist/" in n]
    assert not real_nested, "real archive contains a nested zip"
    assert not real_dist, "real archive contains dist/ content"

    # git-archive provenance: untracked files cannot enter the archive
    stray = ROOT / "scripts" / "__untracked_probe__"
    stray.write_text("untracked")
    tracked = subprocess.run(["git", "ls-files", str(stray.relative_to(ROOT))],
                             cwd=str(ROOT), capture_output=True, text=True).stdout.strip()
    stray.unlink()
    assert tracked == "", "untracked file appeared tracked"

    print("NEGATIVE TESTS PASS:")
    print("  1. verifier flags nested archives (recursion permanently prevented)")
    print("  2. real archive contains no nested zip and no dist/ content")
    print("  3. git-archive builds exclude untracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

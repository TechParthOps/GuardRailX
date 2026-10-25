"""Secret scan over all git-tracked files (content-level). Test fakes excluded."""
import re
import subprocess
import sys

PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI-style key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic-style key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)(password|secret|api_key)\s*[:=]\s*[\"'][^\"']{12,}[\"']"), "credential literal"),
]
SAFE_MARKERS = ("fake", "offline", "example", "redacted", "change-me", "changeme",
                "placeholder", "not-real", "test-", "xxxx")


def main() -> int:
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                           cwd=".").stdout.splitlines()
    hits = 0
    for path in files:
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            for pat, label in PATTERNS:
                m = pat.search(line)
                if m and not any(s in low for s in SAFE_MARKERS) \
                        and "REDACTED" not in line:
                    print(f"{path}:{i}: [{label}] {line.strip()[:90]}")
                    hits += 1
    print(f"--- secret scan hits: {hits} (excluding documented fakes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

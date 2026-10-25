"""Validate the CI workflow: YAML parses, no PowerShell backticks in bash steps,
no PowerShell-continuation syntax, required jobs present."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
wf_path = ROOT / ".github" / "workflows" / "ci.yml"
wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
jobs = wf["jobs"]
print("jobs:", sorted(jobs))

problems = []
for jname, job in jobs.items():
    runs_on = job.get("runs-on", "")
    for step in job.get("steps", []):
        run = step.get("run")
        if not run:
            continue
        if "`" in run:
            problems.append(f"{jname}/{step.get('name')}: PowerShell backtick in shell script")
        if "ubuntu" in str(runs_on) and "\r\n" in run:
            problems.append(f"{jname}/{step.get('name')}: CRLF in bash step")

required = {"offline-tests", "packaging"}
missing = required - set(jobs)
if missing:
    problems.append(f"missing required jobs: {missing}")

if problems:
    print("CI VALIDATION FAILED:")
    for p in problems:
        print("  -", p)
    raise SystemExit(1)
print("ci.yml validation: PASS")

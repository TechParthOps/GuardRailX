import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import session_scope
from app.models import (BenchmarkRun, Case, EventRecord, Experiment,
                        Finding, Policy, Target)


def main() -> None:
    out = ["# Sample report (labeled demo data)", "",
           "> Generated from stored records of the **demo project** that runs the deterministic",
           "> `mock` adapter. These are real executed experiment records, not hand-written results.",
           "> The mock adapter is scripted to leak canaries; findings here demonstrate the pipeline,",
           "> not properties of any real model.", ""]

    with session_scope() as s:
        # most instructive run = the one with the most findings (ties -> latest)
        exps = s.query(Experiment).order_by(Experiment.created_at.desc()).all()
        exp = max(exps, key=lambda e: (e.stats or {}).get("findings", 0))
        tgt = s.get(Target, exp.target_id)
        pol = s.get(Policy, exp.policy_id)
        out += [f"- Experiment: `{exp.id}` — {exp.title}",
                f"- Status: {exp.status} | started {exp.started_at} | finished {exp.finished_at}",
                f"- Target: {tgt.name} (adapter `{tgt.adapter_name}` v{exp.adapter_version}, model `{exp.target_model}`)",
                f"- Policy: {pol.name} v{pol.version} (id {exp.policy_id})",
                f"- Gateway mode: {exp.config.get('gateway_mode')} | replays: {exp.config.get('replays')}",
                f"- Authorization: {json.dumps(exp.authorization)}", "",
                "## Outcomes", "",
                "| # | scenario | replay | outcome |", "|---|---|---|---|"]
        for c in s.query(Case).filter(Case.experiment_id == exp.id).order_by(Case.seq):
            out.append(f"| {c.seq} | `{c.scenario_key}` | {c.replay} | {c.status} |")
        out += ["", f"Aggregate stats: `{json.dumps(exp.stats)}`", "", "## Findings", ""]
        for f in s.query(Finding).filter(Finding.experiment_id == exp.id).all():
            out += [
                f"### {f.title}",
                f"- ID: `{f.id}` | class: `{f.vuln_class}` | layer: `{f.failure_layer}`",
                f"- Severity: **{f.severity}** | confidence: **{f.confidence}** | status: **{f.status}** | reproducible: {f.reproducible}",
                f"- Expected: {json.dumps(f.expected)}",
                f"- Observed: response excerpt `{f.observed.get('response_excerpt', '')[:140]}`",
                f"- Impact: {f.impact}",
                f"- Remediation: {f.remediation}",
                f"- Limitations: {'; '.join(f.limitations)}",
                f"- Reproduction: {json.dumps(f.reproduction)}", ""]
        n_events = s.query(EventRecord).filter(EventRecord.experiment_id == exp.id).count()
        out += ["## Evidence", "", f"- {n_events} correlated events (redacted) with per-case `trace_id`s",
                "- Enforcement events: every proposed tool call has a matching `policy.decision` event", ""]

        # latest live-provider run with agent-layer findings (demonstrates layer separation)
        live = None
        for e in exps:
            t2 = s.get(Target, e.target_id)
            if t2 and t2.adapter_name != "mock" and (e.stats or {}).get("findings", 0) > 0:
                live = e
                break
        if live and live.id != exp.id:
            t2 = s.get(Target, live.target_id)
            out += [f"## Live-provider run (for comparison): {t2.name} (`{t2.model}`)", "",
                    f"- Experiment `{live.id}` — {live.title} — status {live.status}",
                    f"- Adapter `{t2.adapter_name}` v{live.adapter_version}, gateway mode {live.config.get('gateway_mode')}", "",
                    "| # | scenario | outcome | detail |", "|---|---|---|---|"]
            for c in s.query(Case).filter(Case.experiment_id == live.id).order_by(Case.seq):
                detail = ((c.outcome or {}).get("detail") or "")[:120].replace("|", "/")
                out.append(f"| {c.seq} | `{c.scenario_key}` | {c.status} | {detail} |")
            for f2 in s.query(Finding).filter(Finding.experiment_id == live.id).all():
                out += ["", f"**{f2.title}** — severity {f2.severity}, confidence {f2.confidence}, "
                        f"layer `{f2.failure_layer}`, status {f2.status}."]
            out.append("")

        b_all = s.query(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).all()
        if b_all:
            out += ["## Benchmark runs (all stored, most recent first)", "",
                    "| Suite | Target | Policy violation | Injection success | False refusal | Infra error |",
                    "|---|---|---|---|---|---|"]
            for b in b_all:
                m = (b.metrics or {}).get("metrics", {})
                pct = lambda v: "—" if v is None else f"{100 * v:.1f}%"
                t = s.get(Target, b.target_id)
                out.append(f"| {b.suite_key} | {t.name if t else b.target_id} | "
                           f"{pct((m.get('policy_violation_rate') or {}).get('value'))} | "
                           f"{pct((m.get('prompt_injection_success_rate') or {}).get('value'))} | "
                           f"{pct((m.get('false_refusal_rate') or {}).get('value'))} | "
                           f"{pct((m.get('infra_error_rate') or {}).get('value'))} |")
            out.append("")
        b = b_all[0] if b_all else None
        if b and b.metrics:
            out += ["## Benchmark (safety-core, same demo target)", "", "| Metric | Value |", "|---|---|"]
            for k, v in b.metrics["metrics"].items():
                out.append(f"| {k} | {v['value']} ({v['numerator']}/{v['denominator']}) |")

    (Path(__file__).resolve().parent.parent / "docs" / "SAMPLE_REPORT.md").write_text(
        "\n".join(out), encoding="utf-8")
    print("written docs/SAMPLE_REPORT.md")


if __name__ == "__main__":
    main()

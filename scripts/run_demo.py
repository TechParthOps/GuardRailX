import asyncio
import logging

logging.disable(logging.WARNING)

from app.seed import bootstrap, run_demo_experiment

info = bootstrap()
exp_id = asyncio.run(run_demo_experiment(info))
print("demo experiment:", exp_id)

from app.db import session_scope
from app.models import Experiment, Case, Finding

with session_scope() as s:
    e = s.get(Experiment, exp_id)
    print("status:", e.status, "stats:", e.stats)
    for c in s.query(Case).filter(Case.experiment_id == exp_id).order_by(Case.seq).all():
        print(f"  case {c.seq:2d} {c.scenario_key:28s} -> {c.status}")
    for f in s.query(Finding).filter(Finding.experiment_id == exp_id).all():
        print(f"  finding {f.id} [{f.severity}/{f.confidence}] {f.status} reproducible={f.reproducible}: {f.title}")

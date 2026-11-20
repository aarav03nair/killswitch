"""ks.bench: seeds x faults x hold x baselines over the real command path (ADR-06, ADR-06-metrics §4). Owner: tara."""

from .agg import METRICS, aggregate, flatten, render_table
from .baselines import snapshot_plan
from .runner import BASELINES, bench, run_cell

__all__ = ["BASELINES", "METRICS", "aggregate", "bench", "flatten", "render_table", "run_cell", "snapshot_plan"]

"""ks.score: score.json from a run dir (ADR-06-metrics §3). Owner: tara.

The scorer is the only place culprit, schedule and S* meet the run; nothing flows back. Every metric is computed
from the chained records (``record.jsonl`` + the side store for ``ks.alert`` bodies) and the effect ledger, never
from ``alerts.jsonl`` or a wall-clock log. A metric whose inputs are not built yet is the object
``{"unavailable": "<reason>"}``, never 0; ``null`` means "never happened" (e.g. no alert). No floats. Imports
ks.oracle/ks.inject/ks.contracts only (``test_import_lint``).
"""

from .score import SCORE_KEYS, CONTAINMENT_REASONS, score_run, suspend_tick_of, write_score

__all__ = ["SCORE_KEYS", "CONTAINMENT_REASONS", "score_run", "suspend_tick_of", "write_score"]

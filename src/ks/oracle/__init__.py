"""ks.oracle: the S* run and the effect-ledger algebra (ADR-06, ADR-06-metrics §1-2). Owner: tara.

Scorer-side only. ``InjectSpec`` (fault, culprit, t_inject) goes in here and never reaches agents, gateway,
detectors or the record. S* is the pure world (no gateway, taint, monitor, policy or recovery) with the fault off,
written to its own *oracle run dir* (marked ``ORACLE_RUN``; never a security run, never shared with one).
Imports ks.world/ks.inject/ks.state/ks.contracts only; ``test_import_lint`` enforces no taint/monitor/policy/recovery.
"""

from .ledger import (DELIVERED, LedgerBuilder, b_set, delivered, equal, final, fold, g_set, outbox_key, read_ledger,
                     t0_of)
from .realrun import real_ledger
from .run import (ORACLE_MARKER, OracleResult, OracleRunError, is_oracle_run, oracle_self_test, run_pure, run_s_star)

__all__ = ["DELIVERED", "LedgerBuilder", "b_set", "delivered", "equal", "final", "fold", "g_set", "read_ledger",
           "t0_of", "ORACLE_MARKER", "OracleResult", "OracleRunError", "is_oracle_run", "oracle_self_test", "outbox_key", "real_ledger",
           "run_pure", "run_s_star"]

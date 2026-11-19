"""ks.state: versioned SQLite object store (ADR-05 §1-2). Owner: vikram. Gateway-only (rule 8).

``Store`` implements C3 ``StateView``/``StateWriter``; ``Store.side`` is a C3 ``SideStore`` for version values.
B3-04: ``Store.read``/``read_table`` (read rule, X2), ``Store.state_digest`` + ``fold``/``fold_digest``
(reconcile), ``Store.savepoint``/``simulate`` (dry-run re-run simulation).
"""

from .digest import FoldError, fold, fold_digest
from .fields import FieldSchema, SensitiveKeyError
from .side import SqliteSideStore, side_hash
from .store import (
                    RECOVERY_AUTHOR,
                    SCHEMA_VERSION,
                    NotInTransaction,
                    ReadResult,
                    RedactedValue,
                    SeqOrderError,
                    StaleExpect,
                    StateError,
                    Store,
                    open_store,
)

__all__ = [
                    "RECOVERY_AUTHOR",
                    "SCHEMA_VERSION",
                    "FieldSchema",
                    "FoldError",
                    "NotInTransaction",
                    "ReadResult",
                    "RedactedValue",
                    "SensitiveKeyError",
                    "SeqOrderError",
                    "SqliteSideStore",
                    "StaleExpect",
                    "StateError",
                    "Store",
                    "fold",
                    "fold_digest",
                    "open_store",
                    "side_hash",
]

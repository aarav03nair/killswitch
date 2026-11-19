"""ks.state: versioned SQLite object store (ADR-05 §1-2). Owner: vikram. Gateway-only (rule 8).

``Store`` implements C3 ``StateView``/``StateWriter``; ``Store.side`` is a C3 ``SideStore`` for version values.
Read rule, ``state_digest`` helpers and savepoints are B3-04; they build on ``FieldSchema`` and ``Store``.
"""

from .fields import FieldSchema, SensitiveKeyError
from .side import SqliteSideStore, side_hash
from .store import (
                    RECOVERY_AUTHOR,
                    SCHEMA_VERSION,
                    NotInTransaction,
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
                    "NotInTransaction",
                    "RedactedValue",
                    "SensitiveKeyError",
                    "SeqOrderError",
                    "SqliteSideStore",
                    "StaleExpect",
                    "StateError",
                    "Store",
                    "open_store",
                    "side_hash",
]

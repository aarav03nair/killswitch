"""ks.gateway: the reference monitor (ADR-01 §8, ADR-03). Owner: nisha. SKEL-01 ships only the stub.

Seams: ``Gateway.open``/``Gateway.tick`` toward ks.runtime; ``ToolDispatcher`` toward ks.world (B3-37).
"""

from .dispatch import Execution, OutboxRequest, StateSnapshot, StateTxn, ToolDispatcher, ViewProvider
from .stub import Admission, Gateway, InFrame

__all__ = ["Admission", "Execution", "Gateway", "InFrame", "OutboxRequest", "StateSnapshot", "StateTxn",
           "ToolDispatcher", "ViewProvider"]

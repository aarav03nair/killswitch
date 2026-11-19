"""ks.gateway: the reference monitor (ADR-01 §8, ADR-03). Owner: nisha. SKEL-01 ships only the stub.

Seams: ``Gateway.open``/``Gateway.tick`` toward ks.runtime; ``ToolDispatcher`` toward ks.world (B3-37).
"""

from .dispatch import Execution, GatewayTxn, OutboxRequest, StateSnapshot, StateTxn, ToolDispatcher, ViewProvider
from .control import CallableControl, ControlView, StaticControl
from .policy import AllowAll, Policy, Verdict
from .txn import writes_at
from .stub import Admission, Gateway, InFrame

__all__ = ["AllowAll", "CallableControl", "ControlView", "GatewayTxn", "Policy", "StaticControl", "Verdict",
           "writes_at", "Admission", "Execution", "Gateway", "InFrame", "OutboxRequest", "StateSnapshot", "StateTxn",
           "ToolDispatcher", "ViewProvider"]

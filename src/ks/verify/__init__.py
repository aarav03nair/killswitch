"""ks.verify: offline verification of a run dir (ADR-02 §6). Owner: arjun. Exit codes are ``Exit``."""

from ks.contracts import Exit

from .core import verify

__all__ = ["verify", "Exit"]

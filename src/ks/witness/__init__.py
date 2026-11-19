"""ks.witness: the separate witness process and its gateway-side link (ADR-02 §3). Owner: arjun."""

from .link import WitnessError, WitnessLink, open_witness_fds

__all__ = ["WitnessLink", "WitnessError", "open_witness_fds"]

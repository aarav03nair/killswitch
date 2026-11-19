"""ks.runtime: process topology, uids, tick barrier, teardown (ADR-00). Owner: maya.

Imports are lazy so that a child process importing ``ks.runtime.agent_template`` loads only what it needs.
"""

__all__ = ["run"]


def run(**kwargs):
    from .run import run as _run
    return _run(**kwargs)

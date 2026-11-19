"""Gateway <-> witness messages (ADR-00 "Witness cadence", ADR-02 §3). Canonical JSON lines on a path-less
socketpair. Not a contract type yet (see SKEL-01 notes: candidate for contracts 1.2)::

    gw -> wit : {"type":"init","key_seed":<hex>|null}   null = fresh: the witness generates its own key (E4)
    wit -> gw : {"type":"pub","pub":<hex>}
    gw -> wit : {"type":"files"} + SCM_RIGHTS [witness.jsonl fd, witness-heads/ dir fd]
    wit -> gw : {"type":"ready"}
    gw -> wit : {"type":"head","seq":s,"head":h,"tick":t}   once per tick, after the record flush
    wit -> gw : <WitnessCheckpoint line>                    the signed checkpoint is the ack
    gw -> wit : {"type":"close"}
"""

from __future__ import annotations

from typing import Any

from ks.contracts import canonical

__all__ = ["msg", "HEADS_FILE"]

HEADS_FILE = "heads.jsonl"
"""The witness's private head store inside ``witness-heads/`` (0700, witness uid)."""


def msg(type_: str, **fields: Any) -> bytes:
    return canonical.dumps_line({"type": type_, **fields})

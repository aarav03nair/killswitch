"""RT8 full chain rewrite (F6) with the gateway signing key in the attacker's hands (stronger than the threat
model), an unwitnessed tail (g), a keyring swap (h), and a witness stall.

THREAT-MODEL claim defended: "tamper-evident up to the last witnessed head": the witness (own process, own key, E4)
catches a re-signed rewrite at the first witnessed seq >= k; missing or forged witness data fails closed; an
unwitnessed tail is "consistent, not anchored" without the anchor and caught with it; a keyring swap is caught by
``verify --head`` before any signature. A witness stall raises a soft alert and suspends nobody (rule 8).
"""

from __future__ import annotations

import shutil

import pytest

from ks.contracts import GENESIS_HASH, Exit, Record, RunDir
from ks.identity import sign_hex

from .conftest import inproc_run, verify

SKIP = range(12, 18)  # witness pushes withheld for 6 ticks (> witness_stall_ticks = 3)
SNAP_TICK = 16


@pytest.fixture(scope="module")
def rt8(base):
    out, snap = base / "rt8", base / "rt8-snapshot"

    def skip(tick):
        if tick == SNAP_TICK:  # records of tick 12..16 are flushed and unwitnessed: the mid-run snapshot (g)
            shutil.copytree(out, snap, ignore=shutil.ignore_patterns("operator"))
        return tick in SKIP

    res, keys = inproc_run(out, fault="F2+", skip_checkpoint=skip)
    return out, snap, res.anchor.to_canonical().decode(), keys.private("ks.gateway")


def resign(run, k: int, gw_key, edit) -> None:
    """Edit record k, then re-chain and re-sign k..n with the gateway key (agent signatures untouched)."""
    prev, out = GENESIS_HASH, []
    for rec in RunDir(run).records():
        if rec.seq < k:
            out.append(rec.to_canonical() + b"\n")
            prev = rec.hash
            continue
        fields = {f: v for f, v in rec.to_obj().items() if f not in ("prev_hash", "hash", "gw_sig")}
        if rec.seq == k:
            fields = edit(fields)
        r = Record.seal(prev_hash=prev, **fields)
        r = r.with_gw_sig(sign_hex(gw_key, r.signing_bytes()))
        out.append(r.to_canonical() + b"\n")
        prev = r.hash
    (run / "record.jsonl").write_bytes(b"".join(out))


def _evidence_read(run) -> int:
    """seq of the payment record that read the attacker IBAN (the evidence an insider would erase)."""
    return next(r.seq for r in RunDir(run).records() if r.attributed_agent == "payments"
                and any(e.obj == "suppliers:S-17.iban" for e in r.read_set))


def _drop_reads(f):
    return {**f, "read_set": []}


def _copy(src, dst):
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("operator"))
    return dst


def test_rt8_rewrite_with_gateway_key_is_witness(rt8, tmp_path):
    out, _, anchor, gw = rt8
    assert verify(out, anchor)[0] == Exit.OK
    run = _copy(out, tmp_path / "rw")
    k = _evidence_read(run)
    resign(run, k, gw, _drop_reads)
    w = [c.seq for c in RunDir(run).witness() if c.seq >= k]
    code, rep = verify(run, anchor)
    assert code == Exit.WITNESS and rep["first_bad"] == min(w), rep
    code, rep = verify(run)  # without the anchor too: the witness file alone catches it
    assert code == Exit.WITNESS, rep


def test_rt8e_forged_witness_heads(rt8, tmp_path):
    out, _, anchor, gw = rt8
    run = _copy(out, tmp_path / "e")
    k = _evidence_read(run)
    resign(run, k, gw, _drop_reads)
    heads = {r.seq: r.hash for r in RunDir(run).records()}
    from ks.contracts import WitnessCheckpoint
    lines = []
    for c in RunDir(run).witness():  # no witness key: heads rewritten, signature kept (or garbage)
        lines.append(WitnessCheckpoint.model_validate({**c.to_obj(), "head": heads[c.seq]}).to_canonical() + b"\n")
    (run / "witness.jsonl").write_bytes(b"".join(lines))
    code, rep = verify(run, anchor)
    assert code == Exit.WITNESS, rep


def test_rt8f_deleted_witness_fails_closed(rt8, tmp_path):
    out, _, anchor, _ = rt8
    run = _copy(out, tmp_path / "f")
    (run / "witness.jsonl").unlink()
    code, rep = verify(run, anchor)
    assert code != Exit.OK and rep["anchored"] is False, rep


def test_rt8g_unwitnessed_tail_claim_boundary(rt8, tmp_path):
    out, snap, anchor, gw = rt8
    run = _copy(snap, tmp_path / "g")
    last_w = max(c.seq for c in RunDir(run).witness())
    n = len(list(RunDir(run).records()))
    assert n > last_w  # the snapshot has an unwitnessed tail
    resign(run, last_w + 1, gw, lambda f: {**f, "read_set": []})
    code, rep = verify(run)
    assert code == Exit.OK and rep["anchored"] is False, rep  # EXPECTED: "consistent, not anchored"
    code, rep = verify(run, anchor)  # the anchor printed at run end catches it
    assert code == Exit.WITNESS and rep["reason"] in ("head_mismatch", "truncated"), rep


def test_rt8h_keyring_swap_caught_with_head(rt8, tmp_path):
    out, _, anchor, _ = rt8
    run = _copy(out, tmp_path / "h")
    from tests.skeleton.test_tamper import _swap_keyring_and_resign
    _swap_keyring_and_resign(run)
    code, rep = verify(run, anchor)
    assert (code, rep["reason"]) == (Exit.WITNESS, "keyring_mismatch"), rep


def test_rt8_witness_stall_soft_alert_suspends_nobody(rt8):
    out, _, _, _ = rt8
    al = [a for a in (out / "alerts.jsonl").read_text().splitlines() if '"witness_stall"' in a]
    assert al, "no witness_stall alert after 6 withheld checkpoints"
    import json
    assert all(json.loads(a)["hard"] is False for a in al)
    sus = [r.control.target for r in RunDir(out).records() if r.control is not None
           and r.control.op.value == "suspend"]
    assert sus == ["agent:crm"]  # only the F2+ culprit, never because of the stall

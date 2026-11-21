"""SKEL-01: record edits, truncation and a keyring swap are caught by ks verify (RT7, RT8)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import (GENESIS_HASH, SYSTEM_PRINCIPALS, EnvelopeHeader, Exit, KeyEntry, Keyring, Record, RunDir,
                          WitnessCheckpoint)
from ks.identity import pub_hex, sign_hex

from .conftest import ks_verify


def _edit_line(run, k: int, old: bytes, new: bytes) -> None:
    p = run / "record.jsonl"
    lines = p.read_bytes().split(b"\n")
    assert lines[k - 1].count(old) == 1
    lines[k - 1] = lines[k - 1].replace(old, new)
    p.write_bytes(b"\n".join(lines))


def test_one_line_edit_is_tamper_with_first_bad(run_copy, clean_run):
    _edit_line(run_copy, 5, b'"conn_id":"c-1"', b'"conn_id":"c-2"')
    for head in (None, clean_run[1]):
        code, rep = ks_verify(run_copy, head)
        assert (code, rep.reason, rep.first_bad) == (Exit.TAMPER, "hash_mismatch", 5)


def test_editor_style_edit_is_parse_error_not_io(run_copy):
    rec5 = (run_copy / "record.jsonl").read_bytes().split(b"\n")[4]
    h = Record.from_canonical(rec5).hash.encode()
    _edit_line(run_copy, 5, h, h.upper())
    code, rep = ks_verify(run_copy)
    assert (code, rep.reason, rep.first_bad) == (Exit.TAMPER, "parse_error", 5)


def test_deleted_line_is_seq_gap(run_copy):
    p = run_copy / "record.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:6] + lines[7:]))
    code, rep = ks_verify(run_copy)
    assert (code, rep.reason, rep.first_bad) == (Exit.TAMPER, "seq_gap", 7)


def test_truncation_first_bad_is_n_plus_1(run_copy, clean_run):
    p = run_copy / "record.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    n = len(lines) - 3
    p.write_bytes(b"".join(lines[:n]))
    for head in (None, clean_run[1]):
        code, rep = ks_verify(run_copy, head)
        assert (code, rep.reason, rep.first_bad) == (Exit.WITNESS, "truncated", n + 1)
        assert rep.last_witnessed_seq == 16  # tick 7's checkpoint; tick 8 witnessed seq 18 > n


def _swap_keyring_and_resign(run) -> None:
    """RT8(h): an insider with no keys of ours makes new keys for every principal and re-signs everything."""
    rd = RunDir(run)
    cfg = rd.config()
    new = {p: Ed25519PrivateKey.generate() for p in SYSTEM_PRINCIPALS | set(cfg.agents)}
    prev, out, heads = GENESIS_HASH, [], {}
    for rec in rd.records():
        fields = {k: v for k, v in rec.to_obj().items() if k not in ("prev_hash", "hash", "gw_sig")}
        hdr = EnvelopeHeader.model_validate({**fields["envelope"], "sig": None})
        fields["envelope"]["sig"] = sign_hex(new[hdr.agent_id], hdr.signing_bytes())
        r = Record.seal(prev_hash=prev, **fields)
        r = r.with_gw_sig(sign_hex(new["ks.gateway"], r.signing_bytes()))
        out.append(r.to_canonical() + b"\n")
        prev = heads[r.seq] = r.hash
    (run / "record.jsonl").write_bytes(b"".join(out))
    cps = []
    for cp in rd.witness():
        c = WitnessCheckpoint.model_validate({**cp.to_obj(), "head": heads[cp.seq], "sig": None})
        cps.append(c.with_sig(sign_hex(new["ks.witness"], c.signing_bytes())).to_canonical() + b"\n")
    (run / "witness.jsonl").write_bytes(b"".join(cps))
    ring = Keyring(keys=tuple(KeyEntry(principal=p, pub=pub_hex(new[p])) for p in sorted(new)))
    (run / "keys.json").write_bytes(ring.to_canonical())


def test_keyring_swap_caught_only_with_head(run_copy, clean_run):
    _swap_keyring_and_resign(run_copy)
    code, rep = ks_verify(run_copy)
    assert code == Exit.OK and not rep.anchored  # "consistent, not anchored": outside the C1 claim
    code, rep = ks_verify(run_copy, clean_run[1])
    assert (code, rep.reason, rep.anchored) == (Exit.WITNESS, "keyring_mismatch", False)


def test_failure_output_never_says_consistent_or_no_anchor_s4_32(run_copy, clean_run, tmp_path):
    """S4-32: TAMPER and WITNESS, with and without --head: human line and JSON state NOT VERIFIED, never
    'consistent' or no_anchor; the exit code matches."""
    from .conftest import ks
    anchor = clean_run[1]
    _edit_line(run_copy, 5, b'"conn_id":"c-1"', b'"conn_id":"c-2"')
    for head in (None, anchor):
        args = ("verify", run_copy) + (("--head", head) if head else ())
        p = ks(*args)
        line = p.stdout.splitlines()[0]
        assert p.returncode == Exit.TAMPER
        assert line.startswith("verify: TAMPER hash_mismatch at seq 5; NOT VERIFIED")
        assert "consistent" not in line and "no_anchor" not in line and "last witnessed seq 0" not in line
        assert ("--head given" in line) == (head is not None)
        code, rep = ks_verify(run_copy, head)
        assert rep.anchored is False and rep.unanchored_reason == "verify_failed" and rep.first_bad == 5
        assert rep.last_witnessed_seq == 20 and "last witnessed seq 20" in line  # real figure, not 0 / "not reached"
    # WITNESS (truncation): a real witnessed seq is reported
    run2 = tmp_path / "r2"
    import shutil
    shutil.copytree(clean_run[0], run2)
    p = run2 / "record.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-3]))
    for head in (None, anchor):
        out = ks("verify", run2, *(("--head", head) if head else ()))
        line = out.stdout.splitlines()[0]
        assert out.returncode == Exit.WITNESS and "truncated at seq" in line and "NOT VERIFIED" in line
        assert "consistent" not in line
        assert "last witnessed seq 16" in line

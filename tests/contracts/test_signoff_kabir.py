"""Kabir's CON-02 sign-off tests (CALL-02/kabir.md; SEC-03 B1-B4, R1, R4, F1)."""

import errno
import os
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ks.contracts import (
    DETERMINISTIC_FILES, MAX_DEPTH, MAX_EXPIRY_TICKS, VERIFY_REASONS, CanonicalError, Control, ControlOp, EpochFold,
    Exit, KeyEntry, Keyring, ReadEntry, Record, RunAnchor, RunConfig, RunDir, SubmitFrame, TickFrame, VerifyReport,
    WitnessCheckpoint, anchor_status, canonical, decode_frame, determinism_view, expiry_ok, make_obj_id,
    witness_chain_problems,
)
from ks.contracts import rundir as C6

import samples as S


# --- B1 / F2: signed witness count ---------------------------------------------------------------
def _cp(seq, tick, head, count):
    return WitnessCheckpoint(witness_id="ks.witness", seq=seq, tick=tick, head=head, count=count, sig=None)


def test_count_chain():
    recs = S.chain()
    good = [_cp(1, 10, recs[0].hash, 1), _cp(1, 11, recs[0].hash, 2),  # no-op tick: same (seq, head), new count
            _cp(4, 12, recs[3].hash, 3)]
    assert witness_chain_problems(good) == []
    gap = [good[0], _cp(1, 11, recs[0].hash, 3)]
    assert witness_chain_problems(gap) == ["2: count_mismatch"]
    restart = [good[0], _cp(4, 12, recs[3].hash, 1)]
    assert witness_chain_problems(restart) == ["2: count_mismatch"]
    swapped_head = [good[0], _cp(1, 11, recs[1].hash, 2)]
    assert witness_chain_problems(swapped_head) == ["2: witness_mismatch"]
    with pytest.raises(ValueError):  # count starts at 1
        _cp(1, 10, recs[0].hash, 0)
    assert "count" in WitnessCheckpoint.model_fields and "count" not in WitnessCheckpoint.UNSIGNED_FIELDS
    anchor = RunAnchor.of(good[-1], S.keyring(), S.run_config())
    assert anchor.count == 3 and anchor.checkpoint_problems(good[-1]) == []
    assert anchor.checkpoint_problems(good[1]) == ["truncated"]          # F4: cut below the last checkpoint
    assert anchor.checkpoint_problems(None) == ["truncated"]
    assert anchor.checkpoint_problems(_cp(4, 12, recs[2].hash, 3)) == ["head_mismatch"]


# --- B1(b,c) / F1 / RT8(h): anchor binds keyring and config ---------------------------------------
def _fresh_pub(_principal, _cache={}):
    k = _cache.setdefault(_principal, Ed25519PrivateKey.generate())
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def test_rt8h_keyring_swap_detected_by_anchor(tmp_path):
    s = S.samples()
    rd = RunDir.create(tmp_path / "run", s["run_config"], s["keyring"])
    w = S.witness(S.chain()[-1])
    anchor = RunAnchor.of(w, rd.keyring(), rd.config())
    line = anchor.to_canonical()
    assert RunAnchor.from_canonical(line) == anchor and b"\n" not in line  # one canonical line
    assert anchor.problems(rd.keyring(), rd.config()) == []
    # insider swaps keys.json for keys they hold (and would re-sign every record and checkpoint)
    attacker = Keyring(keys=tuple(KeyEntry(principal=p, pub=_fresh_pub(p)) for p in S.PRINCIPALS))
    (rd.path / C6.KEYS).write_bytes(attacker.to_canonical())
    assert anchor.problems(rd.keyring(), rd.config()) == ["keyring_mismatch"]
    assert VERIFY_REASONS["keyring_mismatch"] == Exit.WITNESS
    VerifyReport(ok=False, exit=int(Exit.WITNESS), first_bad=None, reason="keyring_mismatch", last_witnessed_seq=0,
                 anchored=True, unanchored_reason=None)
    edited = S.run_config(hold_window_ticks=0)
    assert anchor.problems(rd.keyring(), edited) == ["keyring_mismatch", "config_mismatch"]
    # unanchored verify can never claim C1
    assert anchor_status(None, rd.config()) == (False, "no_anchor")
    assert anchor_status(anchor, rd.config()) == (True, None)
    with pytest.raises(ValueError):
        VerifyReport(ok=True, exit=0, first_bad=None, reason="ok", last_witnessed_seq=4, anchored=False,
                     unanchored_reason=None)


# --- B2 / C3 / C4 / C5: private keys are never a function of the seed -------------------------------
def _run_with_fresh_keys(path):
    keys = {p: Ed25519PrivateKey.generate() for p in S.PRINCIPALS}

    def pub(p):
        return keys[p].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(p, data):
        return keys[p].sign(data).hex()

    rd = RunDir.create(path, S.run_config(), S.keyring(pub))
    env = S.envelope().model_copy(update={"sig": None})
    env = env.with_sig(sign("crm", env.signing_bytes()))
    r1 = S.record_exec()
    r1 = Record.seal(**{**{k: v for k, v in r1.__dict__.items() if k not in ("hash", "gw_sig")},
                        "envelope": env.header()})
    r1 = r1.with_gw_sig(sign("ks.gateway", r1.signing_bytes()))
    rd.append(r1)
    w = WitnessCheckpoint(witness_id="ks.witness", seq=1, tick=r1.tick, head=r1.hash, count=1, sig=None)
    rd.append(w.with_sig(sign("ks.witness", w.signing_bytes())))
    rd.append(S.alert_invariant())
    rd.write_plan(S.plan())
    rd.write_side(S.samples()["side_value"])
    rd.write(C6.EFFECTS, b'{"n":1}\n')
    rd.write(C6.SCORE, b'{"r":0}')
    rd.write("oracle/s_star.jsonl", b"{}\n")
    return rd


def test_fresh_keys_differ(tmp_path):
    assert C6.KEYS not in DETERMINISTIC_FILES
    assert set(DETERMINISTIC_FILES) == {"config.json", "record.jsonl", "witness.jsonl", "alerts.jsonl",
                                        "effects.jsonl", "oracle/**", "score.json", "plans/**", "sidestore/**"}
    a, b = _run_with_fresh_keys(tmp_path / "a"), _run_with_fresh_keys(tmp_path / "b")
    assert (a.path / C6.KEYS).read_bytes() != (b.path / C6.KEYS).read_bytes()
    assert (a.path / C6.RECORD).read_bytes() != (b.path / C6.RECORD).read_bytes()
    assert (a.path / C6.WITNESS).read_bytes() != (b.path / C6.WITNESS).read_bytes()
    fa, fb = a.determinism_files(), b.determinism_files()
    assert fa == fb
    assert {"config.json", "record.jsonl", "witness.jsonl", "alerts.jsonl", "effects.jsonl", "score.json",
            "oracle/s_star.jsonl"} <= set(fa)
    assert any(k.startswith("plans/") for k in fa) and any(k.startswith("sidestore/") for k in fa)
    view = determinism_view(next(a.records()))
    assert not {"hash", "prev_hash", "gw_sig"} & set(view) and "sig" not in view["envelope"]
    assert set(determinism_view(next(a.witness()))) == {"contract", "witness_id", "seq", "tick", "count"}


# --- B3 / D1 / D3: monotonic epochs ---------------------------------------------------------------
def _ctl(op, epoch, target="agent:crm", n=1, by=None):
    auto = (op == ControlOp.SUSPEND and by is None) or by in ("ks.monitor", "ks.gateway")
    return Control(control_id=f"k-{n:06d}", op=op, target=target, epoch=epoch, alert_id=None,
                   issued_by=by or ("ks.monitor" if auto else "ks.operator"), auto=auto, reason="t")


def test_epoch_monotonic():
    f = EpochFold(["crm", "payments"])
    assert f.epoch("crm") == 0
    f.apply(_ctl(ControlOp.SUSPEND, 1))
    assert f.status("crm") == "suspended" and f.epoch("crm") is None      # TickFrame.epoch None while suspended
    with pytest.raises(ValueError, match="monotonic"):                     # release must not restore epoch 0
        EpochFold(["crm"]).feed([_ctl(ControlOp.SUSPEND, 1), _ctl(ControlOp.RELEASE, 0, n=2)])
    with pytest.raises(ValueError, match="monotonic"):                     # nor reuse the suspend epoch
        EpochFold(["crm"]).feed([_ctl(ControlOp.SUSPEND, 1), _ctl(ControlOp.RELEASE, 1, n=2)])
    f.apply(_ctl(ControlOp.RELEASE, 2, n=2))
    assert f.epoch("crm") == 2 and f.status("crm") == "active"             # fresh epoch
    with pytest.raises(ValueError):                                        # first suspend must exceed 0
        EpochFold(["payments"]).apply(_ctl(ControlOp.SUSPEND, 0, target="agent:payments"))
    f.apply(_ctl(ControlOp.REVOKE, 5, n=3))
    with pytest.raises(ValueError, match="revoked"):
        f.apply(_ctl(ControlOp.RELEASE, 6, n=4))
    f.apply(_ctl(ControlOp.HOLD, None, target="outbox:ob-000001", n=5, by="ks.monitor"))  # ignored
    assert f.epoch("payments") == 0
    TickFrame(tick=3, epoch=None, view=())
    # a presigned pre-suspend envelope is stale after release: its epoch (0) != current (2)
    assert S.envelope(epoch=0).epoch != f.max_epoch("crm")


# --- B3 / D2 / F3: capped expiry (RT4-ready) ----------------------------------------------------------
def test_expiry_cap_and_admitted_expiry():
    assert MAX_EXPIRY_TICKS == 8
    assert expiry_ok(18, 10) and expiry_ok(10, 10)
    assert not expiry_ok(19, 10) and not expiry_ok(9, 10) and not expiry_ok(2**53 - 1, 10)
    base = S.record_exec().to_obj()
    with pytest.raises(ValueError, match="expiry"):  # accepted while expired
        Record.model_validate({**base, "tick": 13})
    far = S.envelope(expiry_tick=10 + MAX_EXPIRY_TICKS + 1)
    with pytest.raises(ValueError, match="expiry"):  # accepted while beyond the cap
        Record.model_validate({**base, "envelope": far.header().to_obj(), "envelope_hash": far.content_hash()})
    # M10: unhold re-execution of a held envelope is exempt (nonce/expiry passed at admission)
    Record.model_validate({**base, "tick": 30, "seq": 9, "record_id": "r-000009", "reexec_of": 3})
    with pytest.raises(ValueError):
        Record.model_validate({**base, "tick": 30, "seq": 9, "record_id": "r-000009", "reexec_of": 9})
    # a deny for expiry is fine (that's how the gateway records it)
    Record.model_validate({**base, "tick": 13, "decision": "deny", "reason": "expired", "read_set": [],
                           "write_set": [], "result_hash": None})


# --- B4 / G7: deep frames are a CanonicalError (-> deny/schema), never RecursionError ------------------
def test_depth_6kb_denied():
    deep = b'{"a":' * 1000 + b"1" + b"}" * 1000
    assert len(deep) < 6200
    frame = b'{"tick":1,"type":"noop","x":' + deep + b"}\n"
    for fn, arg in ((decode_frame, frame), (canonical.loads, deep), (Record.from_canonical, deep),
                    (canonical.loads, b"[" * 1000 + b"]" * 1000), (canonical.loads, b"1" * 5000),
                    (decode_frame, b"[" * 5000 + b"\n")):
        with pytest.raises(CanonicalError):
            fn(arg)
    nested: object = 1
    for _ in range(1000):
        nested = {"a": nested}
    with pytest.raises(CanonicalError):
        canonical.dumps(nested)
    ok = b"[" * MAX_DEPTH + b"]" * MAX_DEPTH
    assert canonical.loads(ok) is not None
    with pytest.raises(CanonicalError):
        canonical.loads(b"[" + ok + b"]")
    assert canonical.loads(b'"' + b"[" * 100 + b'"') == "[" * 100   # brackets inside strings don't count
    assert canonical.loads(b'["\\\\",[1]]') == ["\\", [1]]              # escaped backslash before a quote
    deep_args = S.envelope().to_obj()
    deep_args["args"] = {"x": nested}
    with pytest.raises(CanonicalError):
        decode_frame(b'{"envelope":' + canonical.dumps(deep_args) + b',"tick":1,"type":"submit"}\n')
    with pytest.raises(ValueError):
        SubmitFrame(tick=1, envelope=deep_args)


# --- R1 / X1: no '.' in a pk ------------------------------------------------------------------------
def test_pk_dot_rejected():
    with pytest.raises(ValueError):
        make_obj_id("customers", "C-1.email")       # agent-chosen pk (crm.upsert_customer) colliding with a field
    with pytest.raises(ValueError):
        ReadEntry(obj="customers:C-1.email.x", ver=1, hash=S.H_OLD)
    with pytest.raises(ValueError):
        ReadEntry(obj="customers:C-1.Email", ver=1, hash=S.H_OLD)   # field names are lowercase
    cfg = S.run_config()
    cfg.check_obj("suppliers:S-17.iban")
    cfg.check_obj("customers:C-1")
    with pytest.raises(ValueError, match="sensitive"):
        cfg.check_obj("customers:C-1.email")        # suffix must name a sensitive field of that table
    with pytest.raises(ValueError, match="sensitive"):
        cfg.check_obj("tickets:T-3.iban")


# --- R4 / X7: repro mode is never anchored, never with a rogue ----------------------------------------
def test_repro_forces_unanchored_and_refuses_rogue():
    repro = S.run_config(key_mode="repro")
    anchor = RunAnchor.of(S.witness(S.chain()[-1]), S.keyring(), repro)
    assert anchor_status(anchor, repro) == (False, "repro_keys")
    VerifyReport(ok=True, exit=0, first_bad=None, reason="ok", last_witnessed_seq=4, anchored=False,
                 unanchored_reason="repro_keys")
    with pytest.raises(ValueError, match="rogue"):
        S.run_config(key_mode="repro", fault="rogue")
    S.run_config(fault="rogue")                       # fresh + rogue is the security-run configuration
    with pytest.raises(ValueError):
        S.run_config(key_mode="dev")


# --- F1 / X8: agents get EACCES on every run-dir file ------------------------------------------------
@pytest.fixture
def full_run(tmp_path):
    os.chmod(tmp_path, 0o755)  # pytest's tmp dir is 0700; open the parent so only the run dir's modes count
    s = S.samples()
    rd = RunDir.create(tmp_path / "run", s["run_config"], s["keyring"])
    for r in S.chain():
        rd.append(r)
    rd.append(S.witness(S.chain()[-1]))
    rd.append(S.alert_invariant())
    rd.write_plan(S.plan())
    rd.write_side(s["side_value"])
    rd.write(C6.EFFECTS, b"{}\n")
    rd.write(C6.SCORE, b"{}")
    rd.write("oracle/x/y.json", b"{}")
    return rd


def test_rundir_modes(full_run):
    old = os.umask(0)
    try:
        assert full_run.perm_problems() == []
    finally:
        os.umask(old)
    m = lambda rel: os.stat(full_run.path / rel).st_mode & 0o777
    assert m(".") == 0o711 and m(C6.RECORD) == 0o600 and m(C6.CONFIG) == 0o600 and m(C6.KEYS) == 0o600
    assert m(C6.SIDESTORE_DIR) == 0o700 and m(C6.WITNESS_HEADS_DIR) == 0o700 and m(C6.BASELINES_DIR) == 0o700
    assert m(C6.sidestore_relpath(S.H_NEW)) == 0o600 and m("oracle/x") == 0o700
    assert full_run.validate() == []
    os.chmod(full_run.path / C6.RECORD, 0o644)
    assert full_run.perm_problems() == ["record.jsonl: mode 644"]


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to drop to an agent uid")
def test_rundir_perms_agent_eacces(full_run):
    files = [p for p in sorted(full_run.path.rglob("*")) if p.is_file()]
    targets = [full_run.path] + files
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: become agent uid 60001 and try every path
        try:
            os.close(r)
            os.setgroups([])
            os.setgid(60001)
            os.setuid(60001)
            bad = []
            for p in targets:
                try:
                    if p == full_run.path:
                        os.listdir(p)
                    else:
                        open(p, "rb").close()
                    bad.append(str(p))
                except PermissionError as e:
                    if e.errno != errno.EACCES:
                        bad.append(f"{p}:{e.errno}")
            os.write(w, ("\n".join(bad)).encode())
        finally:
            os._exit(0)
    os.close(w)
    out = b""
    while chunk := os.read(r, 65536):
        out += chunk
    os.close(r)
    os.waitpid(pid, 0)
    assert len(files) >= 10
    assert out.decode() == "", f"agent uid could read: {out.decode()}"


def test_obj_id_rejects_trailing_newline():
    """Kabir sign-off probe: regex must fullmatch, so a trailing newline in a pk is rejected."""
    import pytest
    from ks.contracts.state import make_obj_id
    with pytest.raises(ValueError):
        make_obj_id("customers", "C-1\n")

"""ks.cli: the ``ks`` command (ADR-07). Owner: ishaan. SKEL-01 ships ``run`` and ``verify`` only.

    python3 -m ks run --agents 2 --ticks 10 --seed S --key-mode fresh|repro [--repro-secret FILE] --out RUN
    python3 -m ks verify RUN [--head ANCHOR] [--json]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from ks.contracts import NO_LINEAGE_HOLD_BANNER, CanonicalError, Exit, RunAnchor, RunDir, resolver_label

__all__ = ["main"]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # USAGE (64), not argparse's 2
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(Exit.USAGE)


def _parser() -> argparse.ArgumentParser:
    ap = _Parser(prog="ks")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    r = sub.add_parser("run", help="run agents through the gateway and write a run dir")
    r.add_argument("--scenario", choices=("skeleton", "world"), default="skeleton",
                   help="skeleton (agent_NN) or the 10 ADR-06 world agents")
    r.add_argument("--agents", type=int, default=None, help="default 2 (skeleton) or 10 (world)")
    r.add_argument("--ticks", type=int, default=10)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--key-mode", choices=("fresh", "repro"), default="fresh")
    r.add_argument("--repro-secret", help="0600 file outside the run dir (repro mode only)")
    r.add_argument("--tick-deadline-ms", type=int, default=2000)
    r.add_argument("--run-id", help="config run_id (default <scenario>-s<seed>, so same-seed runs compare equal)")
    r.add_argument("--shared-uid", action="store_true",
                   help="do not separate uids even as root (degraded mode: per-agent attribution void)")
    r.add_argument("--out", help="run dir to create; must not exist (default /run/ks/<run_id> as Linux root, else runs/<run_id>)")
    _pacing(r)
    r.add_argument("--fault", help="inject fault id, e.g. F2+ (ADR-06)")
    r.add_argument("--hold", type=int, help="lineage hold window in ticks")
    r.add_argument("--no-lineage-hold", action="store_true",
                   help="D10 contrast, needs --hold 0: also drop the taint hold so a tainted payment dispatches")
    r.add_argument("--resolver", choices=("off", "ww_rebase/1"), default="off",
                   help="write-write conflict resolver (D-18, ADR-05a); recorded in config.json and labelled")
    r.add_argument("--rogue", metavar="FILE", help="jury Python run in place of --slot")
    r.add_argument("--slot", help="agent replaced by --rogue (default docs)")
    r.add_argument("--decisions", metavar="RUN", help="replay operator decisions of an anchored run")
    r.add_argument("--decisions-head", metavar="ANCHOR", help="that run's RunAnchor line (needed with --decisions)")
    i = sub.add_parser("inject", help="run with a fault or rogue agent (sugar for run --fault/--rogue)")
    i.add_argument("fault", nargs="?", help="fault id, e.g. F2+")
    i.add_argument("--rogue", metavar="FILE")
    i.add_argument("--slot")
    i.add_argument("--culprit", help="restate the fault's culprit (must match the world)")
    i.add_argument("--seed", type=int, default=0)
    i.add_argument("--ticks", type=int, default=120, help="ADR-06-metrics default")
    i.add_argument("--hold", type=int)
    i.add_argument("--with-baselines", action="store_true")
    i.add_argument("--out")
    _pacing(i)
    v = sub.add_parser("verify", help="verify a run dir")
    v.add_argument("run")
    v.add_argument("--head", help="the RunAnchor line printed at the end of ks run")
    v.add_argument("--json", action="store_true", help="print only the VerifyReport line")
    b = sub.add_parser("blame", help="alias: root candidates of a run")
    b.add_argument("run")
    b.add_argument("--alert")
    b.add_argument("--head", help="the RunAnchor line printed at the end of ks run (else: not anchored)")
    c = sub.add_parser("contain", help="suspend|release|revoke|hold|unhold a target on a live run")
    c.add_argument("action", choices=("suspend", "release", "revoke", "hold", "unhold"))
    c.add_argument("target", help="agent:ID, conn:ID, action:r-NNNNNN (unhold) or outbox:ob-NNNNNN")
    c.add_argument("run")
    c.add_argument("--alert")
    c.add_argument("--confirm", action="store_true")
    rc = sub.add_parser("recover", help="dry-run or apply a recovery plan")
    rc.add_argument("run")
    g = rc.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", metavar="PLAN_ID")
    g.add_argument("--unresolve", metavar="PLAN_ID.N",
                   help="plan the undo of an executed resolution (ADR-05a §5); apply it with --apply")
    rc.add_argument("--approve", nargs="+", metavar="ITEM", default=[])
    sc = sub.add_parser("score", help="write score.json for a run")
    sc.add_argument("run")
    sc.add_argument("--json", action="store_true")
    rp = sub.add_parser("repro", help="compare determinism views of two run dirs")
    rp.add_argument("run_a")
    rp.add_argument("run_b")
    bn = sub.add_parser("bench", help="seeds x faults x hold benchmark")
    bn.add_argument("--seeds", default="1-20", help="csv and/or ranges: 1-20 or 1,2,5 (ADR-06-metrics: 1..20)")
    bn.add_argument("--faults", default="F2+,F2+c,F2+x,F3", help="csv of F1,F2,F2+,F2+c,F2+x,F3,F4,F7 or 'all'")
    bn.add_argument("--hold", default="6", help="csv of hold windows H (ADR-06-metrics: 0,6)")
    bn.add_argument("--baselines", default="system,snapshot,revert_culprit_only,no_op")
    bn.add_argument("--ticks", type=int, default=120)
    bn.add_argument("--out", default="runs/bench")
    bn.add_argument("--keep-runs", action="store_true")
    bn.add_argument("--contrast", default="", help="csv of faults: add a system H=0 --no-lineage-hold row (D10 contrast)")
    bn.add_argument("--resolver-faults", default="",
                    help="csv of faults: add a system column run with --resolver ww_rebase/1 (D-18 after-row)")
    co = sub.add_parser("console", help="incident console: static HTML or live terminal view")
    co.add_argument("run")
    cg = co.add_mutually_exclusive_group(required=True)
    cg.add_argument("--html", metavar="OUT")
    cg.add_argument("--live", action="store_true")
    co.add_argument("--once", action="store_true")
    co.add_argument("--pace", action="store_true", help="with --live: stop at each of the 5 beats until Enter")
    return ap


def _pacing(p) -> None:
    p.add_argument("--pause-at", metavar="TICK,...", help="pause the live gateway before these ticks")
    p.add_argument("--step", action="store_true", help="pause between every tick")
    p.add_argument("--pause-on-alert", action="store_true",
                   help="with a fault: pause before the tick after the monitor's first suspend (operator beat)")


def _csv_ints(text: str, flag: str) -> list[int]:
    try:
        vals = [int(x) for x in text.split(",")]
    except ValueError:
        raise ValueError(f"{flag} wants comma separated integers, got {text!r}") from None
    if not vals or any(v < 0 for v in vals):
        raise ValueError(f"{flag} wants non-negative integers, got {text!r}")
    return vals


def _usage(cmd: str, msg: str) -> int:
    print(f"ks {cmd}: {msg}", file=sys.stderr)
    return Exit.USAGE


def _not_yet(cmd: str, what: str) -> int:
    """Stable placeholder: the CLI adds no exit code (ADR-07), so an unbuilt feature is IO with a fixed message."""
    print(f"ks {cmd}: not yet implemented ({what})", file=sys.stderr)
    return Exit.IO


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handler = {"run": _run, "verify": _verify, "inject": _inject, "blame": _blame, "contain": _contain,
               "recover": _recover, "score": _score, "repro": _repro, "bench": _bench,
               "console": _console}[args.cmd]
    return handler(args)


def _options(cmd: str, args, **kw):
    """Build ks.runtime.RunOptions from the parsed flags; (options, None) or (None, exit code)."""
    from ks.runtime import RunOptions
    try:
        return RunOptions(**kw), None
    except ValueError as e:
        return None, _usage(cmd, str(e))


def _check_fault(cmd: str, fault: str, seed: int, ticks: int, culprit: str | None) -> int | None:
    from ks.inject import world_fault
    from ks.inject.spec import make_spec
    try:
        make_spec(world_fault(fault), seed, ticks=max(ticks, 1), culprit=culprit)
    except ValueError as e:
        return _usage(cmd, str(e))
    return None


def _run(args) -> int:
    if args.rogue and args.key_mode == "repro":
        return _usage("run", "--rogue forces fresh keys; it cannot be combined with --key-mode repro")
    if args.slot and not args.rogue:
        return _usage("run", "--slot needs --rogue")
    if args.fault and args.scenario != "world":
        return _usage("run", "--fault needs --scenario world")
    kw: dict = {}
    try:
        if args.pause_at is not None:
            kw["pause_at"] = tuple(_csv_ints(args.pause_at, "--pause-at"))
    except ValueError as e:
        return _usage("run", str(e))
    if args.fault and (err := _check_fault("run", args.fault, args.seed, args.ticks, None)) is not None:
        return err
    if args.rogue:
        if not os.path.isfile(args.rogue):
            return _usage("run", f"--rogue file not found: {args.rogue}")
        kw.update(rogue=args.rogue, slot=args.slot or "docs")
    opts, err = _options("run", args, fault=args.fault or None, hold=args.hold, step=args.step,
                         no_lineage_hold=args.no_lineage_hold, resolver=args.resolver,
                         monitor=bool(args.fault or args.rogue),  # B3-27/B3-35: fault and rogue runs are monitored
                         pause_on_alert=args.pause_on_alert,
                         decisions=args.decisions, decisions_head=args.decisions_head, **kw)
    return err if err is not None else _launch("run", args, opts)


def _launch(cmd: str, args, opts) -> int:
    import ks.runtime
    run = ks.runtime.run  # patchable seam; callable whatever the import order (B3-12, maya's __init__ fix)
    from ks.runtime.setup import default_out, default_run_id
    run_id = args.run_id
    out = args.out or default_out(run_id or default_run_id(args.scenario, args.seed))
    try:
        run(agents=args.agents, ticks=args.ticks, seed=args.seed, key_mode=args.key_mode, out=out,
            repro_secret=args.repro_secret, tick_deadline_ms=args.tick_deadline_ms,
            separate_uids=False if args.shared_uid else None, run_id=run_id, scenario=args.scenario, options=opts)
    except NotImplementedError as e:
        return _not_yet(cmd, str(e))
    except ValueError as e:
        print(f"ks {cmd}: {e}", file=sys.stderr)
        return Exit.USAGE
    except (OSError, RuntimeError) as e:
        print(f"ks {cmd}: {e}", file=sys.stderr)
        return Exit.IO
    return Exit.OK


def _verify(args) -> int:
    from ks.verify import verify
    anchor = None
    if args.head is not None:
        try:
            anchor = RunAnchor.from_canonical(args.head.strip().encode())
        except CanonicalError as e:
            print(f"ks verify: --head is not a RunAnchor line: {e}", file=sys.stderr)
            return Exit.USAGE
    rep = verify(args.run, anchor)
    if not args.json:
        where = f" at seq {rep.first_bad}" if rep.first_bad is not None else ""
        if rep.ok:
            scope = "anchored" if rep.anchored else f"consistent, not anchored ({rep.unanchored_reason})"
            print(f"verify: OK; last witnessed seq {rep.last_witnessed_seq}; {scope}")
        else:  # S4-32: a failure is never "consistent", and says whether a --head was given
            if rep.last_witnessed_seq:
                wit = f"last witnessed seq {rep.last_witnessed_seq} (signed checkpoints)"
            else:
                wit = f"witness not checked (verify stopped{' at seq ' + str(rep.first_bad) if rep.first_bad else ''})"
            given = "--head given, run still fails" if args.head is not None else "no --head"
            print(f"verify: {Exit(rep.exit).name} {rep.reason}{where}; NOT VERIFIED ({given}); {wit}")
        try:  # ADR-05a §7 label (config.json; verify itself checked it above when readable)
            print(resolver_label(RunDir(args.run).config().resolver))
        except Exception:  # noqa: BLE001 - unreadable config: the verdict line already says so
            pass
        if not rep.lineage_hold:
            print(f"!! {NO_LINEAGE_HOLD_BANNER}")
    print(rep.to_canonical().decode())
    return rep.exit


def _inject(args) -> int:
    if bool(args.fault) == bool(args.rogue):
        return _usage("inject", "give exactly one of FAULT or --rogue FILE")
    kw: dict = {}
    try:
        if args.pause_at is not None:
            kw["pause_at"] = tuple(_csv_ints(args.pause_at, "--pause-at"))
    except ValueError as e:
        return _usage("inject", str(e))
    run_id = None
    if args.fault:
        if (err := _check_fault("inject", args.fault, args.seed, args.ticks, args.culprit)) is not None:
            return err
        from ks.inject import world_fault
        kw.update(fault=args.fault, culprit=args.culprit, monitor=True)
        run_id = f"world-{world_fault(args.fault)}-s{args.seed}"
    else:
        if args.culprit:
            return _usage("inject", "--culprit applies to a fault, not --rogue")
        if not os.path.isfile(args.rogue):
            return _usage("inject", f"--rogue file not found: {args.rogue}")
        kw.update(rogue=args.rogue, slot=args.slot or "docs", monitor=True)
        run_id = f"world-rogue-{args.slot or 'docs'}-s{args.seed}"
    opts, err = _options("inject", args, hold=args.hold, step=args.step, with_baselines=args.with_baselines,
                         pause_on_alert=args.pause_on_alert, **kw)
    if err is not None:
        return err
    ns = argparse.Namespace(scenario="world", agents=None, ticks=args.ticks, seed=args.seed, key_mode="fresh",
                            repro_secret=None, tick_deadline_ms=2000, run_id=run_id, shared_uid=False, out=args.out)
    return _launch("inject", ns, opts)


def _need_run(cmd: str, run: str) -> int | None:
    if not os.path.isdir(run):
        print(f"ks {cmd}: no such run dir: {run}", file=sys.stderr)
        return Exit.IO
    return None


def _blame(args) -> int:
    """S4-29: read-only. Chained alerts -> ranked root_candidates and the forward taint summary (ks.taint)."""
    if (err := _need_run("blame", args.run)) is not None:
        return err
    from ks.contracts import RunDir
    from ks.runtime.recover import _alerts
    from ks.taint import RecordIndex, root_candidates, taint_from_alerts
    from ks.verify import verify
    anchor = None
    if args.head is not None:
        try:
            anchor = RunAnchor.from_canonical(args.head.strip().encode())
        except CanonicalError as e:
            print(f"ks blame: --head is not a RunAnchor line: {e}", file=sys.stderr)
            return Exit.USAGE
    rep = verify(args.run, anchor, log=lambda s: None)  # blame recomputes from the record: refuse on an unverified one
    if not rep.ok:
        where = f" at seq {rep.first_bad}" if rep.first_bad is not None else ""
        print(f"ks blame: UNVERIFIED RECORD: verify {rep.reason}{where}. Refusing to name a culprit from a record "
              f"that does not verify (run `ks verify {args.run}`).", file=sys.stderr)
        return rep.exit if rep.exit else Exit.IO
    void = rep.isolation == "degraded"
    scope = "anchored" if rep.anchored else f"consistent, not anchored ({rep.unanchored_reason})"
    print(f"verify: OK; isolation {rep.isolation or 'unknown'}; {scope}; last witnessed seq {rep.last_witnessed_seq}")
    if void:
        print("!! per-agent attribution VOID for this run (isolation degraded): nothing below is attributed to an "
              "agent. Candidates are listed only as 'unattributed: isolation degraded'.")
    elif not rep.anchored:
        print("note: not anchored: tamper-evident up to the last witnessed head only; pass --head ANCHOR for the "
              "full claim.")
    try:
        records = list(RunDir(args.run).records())
        alerts = _alerts(Path(args.run), records)
    except (OSError, ValueError, KeyError) as e:
        print(f"ks blame: not a readable run dir: {e}", file=sys.stderr)
        return Exit.IO
    if args.alert:
        alerts = [a for a in alerts if a.alert_id == args.alert]
    if not alerts:
        print("ks blame: no chained ks.alert in the record" + (f" with id {args.alert}" if args.alert else ""),
              file=sys.stderr)
        return Exit.IO
    ix = RecordIndex.of(records)
    for a in alerts:
        print(f"alert {a.alert_id}: {a.detector}")
        rc = root_candidates(ix, a.evidence_versions)
        print("root candidates (unattributed: isolation degraded):" if void else "root candidates (ranked):")
        for i, c in enumerate(rc, 1):
            print(f"  {i}. {c}" + ("  [unattributed: isolation degraded]" if void else ""))
        if not rc:
            print("  (none)")
    t = taint_from_alerts(ix, alerts)
    if t is None:
        print("taint: none (no suspended suspect, so no seed)")
    else:
        print(f"suspect {t.suspect}: t0 seq {t.t0_seq_est}, suspended at seq {t.suspend_seq}"
              + (" [unattributed: isolation degraded]" if void else ""))
        print(f"taint: {len(t.versions)} versions, {len(t.actions)} actions, {len(t.outbox_ids)} outbox items; "
              f"agents with tainted actions: {', '.join(t.agents) or 'none'}"
              + (" [unattributed: isolation degraded]" if void and t.agents else ""))
    return Exit.OK


def _contain(args) -> int:
    if not (args.target.startswith(("agent:", "conn:", "action:", "outbox:")) and len(args.target.split(":", 1)[1]) > 0):
        return _usage("contain", "TARGET must be agent:ID, conn:ID, action:r-NNNNNN or outbox:ob-NNNNNN")
    if args.action == "revoke" and not args.confirm:
        return _usage("contain", "revoke needs --confirm")
    if (err := _need_run("contain", args.run)) is not None:
        return err
    from ks.contracts import canonical
    from ks.runtime.operator import operator_request
    req: dict = {"op": args.action, "target": args.target}
    if args.alert is not None:
        req["alert_id"] = args.alert
    if args.confirm:
        req["confirm"] = True
    try:  # J1: the only way in; the gateway signs it as ks.operator and records it on c-0
        reply = operator_request(args.run, req)
    except (OSError, CanonicalError) as e:
        print(f"ks contain: no live run at {args.run} (operator socket: {e})", file=sys.stderr)
        return Exit.IO
    print(canonical.dumps(reply).decode())
    if reply.get("pending"):  # never report a false outcome: the request is queued and may still land
        print("ks contain: PENDING: not yet admitted; it may still be recorded. Check record.jsonl before retrying.",
              file=sys.stderr)
        return Exit.IO
    if not reply.get("ok"):
        print(f"ks contain: refused: {reply.get('error') or reply.get('reason')}", file=sys.stderr)
        return Exit.IO
    return Exit.OK


def _recover(args) -> int:
    """ADR-07 / ADR-05 §7-8 (B3-30): verify first (FROZEN on a non-OK result or a tamper/stall alert, F5); then
    ``--dry-run`` writes ``plans/<plan_id>.json`` and prints the diff and the apply line, or ``--apply PLAN_ID``
    approves (``ks.approve`` as ks.operator) and runs the approved steps on the live gateway (J1 socket)."""
    if (err := _need_run("recover", args.run)) is not None:
        return err
    from ks.contracts import canonical
    from ks.runtime import recover as R
    why = R.frozen(args.run)
    if why is not None and why.startswith(("verify missing_file", "verify unreadable")):
        print(f"ks recover: not a readable run dir: {why}", file=sys.stderr)
        return Exit.IO
    if why is not None:
        print(f"ks recover: FROZEN: {why} (M12: no recovery for the rest of this run)", file=sys.stderr)
        return Exit.FROZEN
    if args.unresolve:
        if args.approve:
            return _usage("recover", "--approve goes with --apply")
        try:
            res = R.cli_unresolve(args.run, args.unresolve)
        except (ValueError, OSError) as e:
            print(f"ks recover: {e}", file=sys.stderr)
            return Exit.IO
        sys.stdout.write(res.text)
        print(f"plan written: {res.path}")
        if res.plan.steps[0].op == "flag":
            print("ks recover: unresolve_blocked: a person decides (the resolution stays)", file=sys.stderr)
            return Exit.IO
        print(f"apply: ks recover {args.run} --apply {res.plan.plan_id}")
        return Exit.OK
    if args.dry_run:
        if args.approve:
            return _usage("recover", "--approve goes with --apply")
        try:
            res = R.cli_dry_run(args.run)
        except (ValueError, OSError) as e:
            print(f"ks recover: {e}", file=sys.stderr)
            return Exit.IO
        sys.stdout.write(res.text)
        print(f"plan written: {res.path}")
        if res.stale:
            print("ks recover: hold/stale_plan in the dry-run: not applicable as is", file=sys.stderr)
            return Exit.IO
        extra = " ".join(str(n) for n in res.plan.needs_approval)
        print(f"apply: ks recover {args.run} --apply {res.plan.plan_id}"
              + (f"  [--approve {extra}]  (steps needing a person: {extra})" if extra else ""))
        return Exit.OK
    try:
        approve = [int(x) for x in args.approve]
    except ValueError:
        return _usage("recover", "--approve takes step numbers")
    try:
        plan, a, r = R.cli_apply(args.run, args.apply, approve)
    except ValueError as e:
        return _usage("recover", str(e))
    except (OSError, CanonicalError) as e:
        print(f"ks recover: no live run at {args.run} (operator socket: {e}); a finished run is dry-run only",
              file=sys.stderr)
        return Exit.IO
    print(canonical.dumps({"approve": a, "recover": r}).decode())
    if a.get("pending") or r.get("pending"):
        print("ks recover: PENDING: not yet admitted; check record.jsonl before retrying", file=sys.stderr)
        return Exit.IO
    if not a.get("ok"):
        print(f"ks recover: approval refused: {a.get('error') or a.get('reason')}", file=sys.stderr)
        return Exit.IO
    if not r.get("ok"):
        bad = next((s for s in r.get("steps", []) if s.get("ok") is not True), r)
        if bad.get("reason") == "recovery_frozen":
            print("ks recover: FROZEN (deny/recovery_frozen)", file=sys.stderr)
            return Exit.FROZEN
        print(f"ks recover: apply halted: {bad.get('decision', '')}/{bad.get('reason') or bad.get('error')}"
              f" at seq {bad.get('seq', '-')}; build a new plan (ks recover {args.run} --dry-run)", file=sys.stderr)
        return Exit.IO
    print(f"ks recover: plan {plan.plan_id} applied: {len(r.get('steps', []))} steps recorded")
    for st in r.get("steps", []):  # B3-27: re-held items leave only by an unhold (X4); say how
        for eff in (st.get("result") or {}).get("effects") or []:
            if len(eff) == 2 and eff[1] == "reheld":
                print(f"re-held, review then release: ks contain unhold outbox:{eff[0]} {args.run}")
    try:
        for oid in R.restored_releasable(args.run):
            print(f"held for a changed bank field, now restored: ks contain unhold outbox:{oid} {args.run}")
    except (OSError, ValueError) as e:  # advisory only: the apply itself is recorded
        print(f"ks recover: could not list restored holds: {e}", file=sys.stderr)
    return Exit.OK


def _score(args) -> int:
    """B3-27: score.json for a fault run (ADR-06-metrics §3): S* (fault off, the culprit's suspension mirrored, same
    hold) in ``RUN/oracle/s-star`` (reused if already there), then ``ks.score.score_run`` and ``write_score``."""
    if (err := _need_run("score", args.run)) is not None:
        return err
    from ks.contracts import RunDir, canonical
    from ks.inject import make_spec, world_fault
    from ks.oracle import run_s_star
    from ks.oracle.ledger import read_ledger
    from ks.oracle.run import EFFECTS
    from ks.score import score_run, suspend_tick_of, write_score
    run = Path(args.run)
    try:
        cfg = RunDir(run).config()
    except Exception as e:  # noqa: BLE001 - unreadable or malformed run dir
        print(f"ks score: {e}", file=sys.stderr)
        return Exit.IO
    from ks.verify import verify
    rep = verify(run, log=lambda s: None)  # S4-33: score reads state.db history; refuse a run that does not verify
    if not rep.ok:
        where = f" at seq {rep.first_bad}" if rep.first_bad is not None else ""
        print(f"ks score: UNVERIFIED RUN: verify {rep.reason}{where}. No headline fields are emitted for a run that "
              f"does not verify (run `ks verify {args.run}`).", file=sys.stderr)
        return rep.exit if rep.exit else Exit.IO
    if cfg.fault is None:
        return _usage("score", "score needs a fault or rogue run (ks run --scenario world --fault F | --rogue FILE)")
    hold = cfg.hold_window_ticks
    rogue_run = cfg.fault == "rogue"
    if rogue_run:  # B3-50: S* = the honest world (hero schedule as the run used it), slot no-op from tick 0
        from ks.inject import rogue_spec
        from ks.runtime.setup import hero_tick
        spec = rogue_spec(cfg.seed, cfg.ticks, cfg.culprit, hero_tick(cfg.seed, cfg.ticks))
    else:
        spec = make_spec(world_fault(cfg.fault), cfg.seed, ticks=cfg.ticks, culprit=cfg.culprit,
                         t_inject=cfg.fault_tick)
    star_dir = run / "oracle" / "s-star"
    try:
        if (star_dir / EFFECTS).is_file():
            star = read_ledger(star_dir / EFFECTS)
        else:
            st = 0 if rogue_run else suspend_tick_of(run, spec.culprit)
            star = run_s_star(spec, star_dir, suspend_tick=st, hold=hold).effects
        s = score_run(run, spec, star, hold=hold)
        path = write_score(run, s)
    except (OSError, ValueError) as e:
        print(f"ks score: {e}", file=sys.stderr)
        return Exit.IO
    if args.json:
        print(canonical.dumps(s).decode())
        return Exit.OK
    if not cfg.lineage_hold:  # contracts 1.6 (B3-51): score.json keeps its schema; config.json carries the switch
        print(f"!! {NO_LINEAGE_HOLD_BANNER}")
    from ks.validity import run_validity, validity_line
    if (vl := validity_line(v := run_validity(run))) is not None:  # S4-22: VOID / DEGRADED is never the headline
        print(("!! " if v["verdict"] != "OK" else "") + vl)
    for k in ("tti_detect", "tti_attribute", "ttc", "R", "C", "post_alert_tainted_effects",
              "irreversible_tainted_released", "reemitted", "kept_without_redo", "false_accusations"):
        print(f"{k:32} {canonical.dumps(s[k]).decode()}")
    print(f"score written: {path}")
    return Exit.OK


def _ranges(text: str, flag: str) -> list[int]:
    out: list[int] = []
    for part in text.split(","):
        lo, sep, hi = part.partition("-")
        try:
            out += list(range(int(lo), int(hi) + 1)) if sep else [int(lo)]
        except ValueError:
            raise ValueError(f"{flag}: not an integer list or range: {text!r}") from None
    return out


def _bench(args) -> int:
    """B3-33: seeds x faults x hold x baselines over the real command path; per-seed score.json, bench.json, bench.md."""
    from ks.bench import BASELINES, bench
    from ks.bench.runner import DEFAULT_FAULTS
    try:
        seeds = _ranges(args.seeds, "--seeds")
        holds = _ranges(args.hold, "--hold")
    except ValueError as e:
        return _usage("bench", str(e))
    faults = list(DEFAULT_FAULTS) if args.faults == "all" else args.faults.split(",")
    bases = args.baselines.split(",")
    if not seeds or any(f not in DEFAULT_FAULTS for f in faults) or any(b not in BASELINES for b in bases):
        return _usage("bench", f"faults must be in {DEFAULT_FAULTS}, baselines in {BASELINES} (F5/F6: ks verify)")
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        return _usage("bench", f"--out {out} exists and is not empty")
    s = bench(seeds, faults, holds, bases, args.ticks, out, keep_runs=args.keep_runs,
              contrast_faults=[x for x in args.contrast.split(",") if x], log=lambda m: print(m, flush=True),
              resolver_faults=[x for x in args.resolver_faults.split(",") if x])
    print((out / "bench.md").read_text())
    print(f"bench written: {out}/bench.json, bench.md, timings.json")
    return Exit.IO if s["failures"] else Exit.OK


def _console(args) -> int:
    if args.once and not args.live:
        return _usage("console", "--once needs --live")
    if args.pace and not args.live:
        return _usage("console", "--pace needs --live")
    if (err := _need_run("console", args.run)) is not None:
        return err
    from ks.console import run_live, write_html
    try:
        if args.html:
            write_html(args.run, args.html)
            return Exit.OK
        return run_live(args.run, once=args.once, pace=args.pace)
    except KeyboardInterrupt:
        return Exit.OK
    except (OSError, ValueError, KeyError) as e:  # not a run dir, unreadable or malformed file
        print(f"ks console: {e}", file=sys.stderr)
        return Exit.IO


def _repro(args) -> int:
    from ks.contracts import RunDir
    print("NOT A SECURITY RUN: ks repro compares seeded runs for determinism; repro-key runs are never anchored.")
    for r in (args.run_a, args.run_b):
        if (err := _need_run("repro", r)) is not None:
            return err
    try:
        a, b = (RunDir(r).determinism_files() for r in (args.run_a, args.run_b))
    except Exception as e:  # unreadable or malformed run dir
        print(f"ks repro: {e}", file=sys.stderr)
        return Exit.IO
    diff = sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))
    if diff:
        print(f"repro: DIVERGED in {len(diff)} file(s): {', '.join(diff)}")
        return Exit.DIVERGED
    print(f"repro: OK; {len(a)} deterministic files identical")
    return Exit.OK

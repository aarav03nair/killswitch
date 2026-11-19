"""ks.cli: the ``ks`` command (ADR-07). Owner: ishaan. SKEL-01 ships ``run`` and ``verify`` only.

    python3 -m ks run --agents 2 --ticks 10 --seed S --key-mode fresh|repro [--repro-secret FILE] --out RUN
    python3 -m ks verify RUN [--head ANCHOR] [--json]
"""

from __future__ import annotations

import argparse
import os
import sys

from ks.contracts import CanonicalError, Exit, RunAnchor

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
    r.add_argument("--rogue", metavar="FILE", help="jury Python run in place of --slot")
    r.add_argument("--slot", help="agent replaced by --rogue (default docs)")
    r.add_argument("--decisions", metavar="RUN", help="replay operator decisions of an anchored run")
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
    c = sub.add_parser("contain", help="suspend|release|revoke a target on a live run")
    c.add_argument("action", choices=("suspend", "release", "revoke"))
    c.add_argument("target", help="agent:ID or conn:ID")
    c.add_argument("run")
    c.add_argument("--alert")
    c.add_argument("--confirm", action="store_true")
    rc = sub.add_parser("recover", help="dry-run or apply a recovery plan")
    rc.add_argument("run")
    g = rc.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", metavar="PLAN_ID")
    rc.add_argument("--approve", nargs="+", metavar="ITEM", default=[])
    sc = sub.add_parser("score", help="write score.json for a run")
    sc.add_argument("run")
    sc.add_argument("--json", action="store_true")
    rp = sub.add_parser("repro", help="compare determinism views of two run dirs")
    rp.add_argument("run_a")
    rp.add_argument("run_b")
    bn = sub.add_parser("bench", help="seeds x faults x hold benchmark")
    bn.add_argument("--seeds", default="0,1,2")
    bn.add_argument("--faults", default="F2+")
    bn.add_argument("--hold", default=None)
    co = sub.add_parser("console", help="incident console: static HTML or live terminal view")
    co.add_argument("run")
    cg = co.add_mutually_exclusive_group(required=True)
    cg.add_argument("--html", metavar="OUT")
    cg.add_argument("--live", action="store_true")
    co.add_argument("--once", action="store_true")
    return ap


def _pacing(p) -> None:
    p.add_argument("--pause-at", metavar="TICK,...", help="pause the live gateway before these ticks")
    p.add_argument("--step", action="store_true", help="pause between every tick")


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
                         decisions=args.decisions, **kw)
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
        scope = "anchored" if rep.anchored else f"consistent, not anchored ({rep.unanchored_reason})"
        verdict = "OK" if rep.ok else f"{Exit(rep.exit).name} {rep.reason}{where}"
        print(f"verify: {verdict}; last witnessed seq {rep.last_witnessed_seq}; {scope}")
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
        kw.update(fault=args.fault, culprit=args.culprit)
        run_id = f"world-{world_fault(args.fault)}-s{args.seed}"
    else:
        if args.culprit:
            return _usage("inject", "--culprit applies to a fault, not --rogue")
        if not os.path.isfile(args.rogue):
            return _usage("inject", f"--rogue file not found: {args.rogue}")
        kw.update(rogue=args.rogue, slot=args.slot or "docs")
    opts, err = _options("inject", args, hold=args.hold, step=args.step, with_baselines=args.with_baselines, **kw)
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
    return _need_run("blame", args.run) or _not_yet("blame", "needs monitor alerts, B3-14")


def _contain(args) -> int:
    if not (args.target.startswith(("agent:", "conn:")) and len(args.target.split(":", 1)[1]) > 0):
        return _usage("contain", "TARGET must be agent:ID or conn:ID")
    if args.action == "revoke" and not args.confirm:
        return _usage("contain", "revoke needs --confirm")
    return _need_run("contain", args.run) or _not_yet("contain", "needs the operator socket, B3-13")


def _recover(args) -> int:
    return _need_run("recover", args.run) or _not_yet("recover", "needs the recovery engine, B3-18+")


def _score(args) -> int:
    return _need_run("score", args.run) or _not_yet("score", "needs ks.score")


def _bench(args) -> int:
    try:
        _csv_ints(args.seeds, "--seeds")
        if args.hold is not None:
            _csv_ints(args.hold, "--hold")
    except ValueError as e:
        return _usage("bench", str(e))
    return _not_yet("bench", "needs ADR-06 metrics runner")


def _console(args) -> int:
    if args.once and not args.live:
        return _usage("console", "--once needs --live")
    return _need_run("console", args.run) or _not_yet("console", "ks.console is B3 console work")


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

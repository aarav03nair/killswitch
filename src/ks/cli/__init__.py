"""ks.cli: the ``ks`` command (ADR-07). Owner: ishaan. SKEL-01 ships ``run`` and ``verify`` only.

    python3 -m ks run --agents 2 --ticks 10 --seed S --key-mode fresh|repro [--repro-secret FILE] --out RUN
    python3 -m ks verify RUN [--head ANCHOR] [--json]
"""

from __future__ import annotations

import argparse
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
    v = sub.add_parser("verify", help="verify a run dir")
    v.add_argument("run")
    v.add_argument("--head", help="the RunAnchor line printed at the end of ks run")
    v.add_argument("--json", action="store_true", help="print only the VerifyReport line")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "run":
        return _run(args)
    return _verify(args)


def _run(args) -> int:
    from ks.runtime import run
    from ks.runtime.setup import default_out, default_run_id
    out = args.out or default_out(args.run_id or default_run_id(args.scenario, args.seed))
    try:
        run(agents=args.agents, ticks=args.ticks, seed=args.seed, key_mode=args.key_mode, out=out,
            repro_secret=args.repro_secret, tick_deadline_ms=args.tick_deadline_ms,
            separate_uids=False if args.shared_uid else None, run_id=args.run_id, scenario=args.scenario)
    except ValueError as e:
        print(f"ks run: {e}", file=sys.stderr)
        return Exit.USAGE
    except (OSError, RuntimeError) as e:
        print(f"ks run: {e}", file=sys.stderr)
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

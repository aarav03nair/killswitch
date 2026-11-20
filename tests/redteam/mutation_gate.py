"""S4-21 mutation gate: every defence has a red-team test that fails when the defence is switched off.

    python3 tests/redteam/mutation_gate.py [--only ID,ID] [--jobs N] [--worktree] [--keep] [--no-build]
    make mutation-gate

What it does, never touching the main tree:

1. Snapshots the working tree's ``pyproject.toml``, ``Dockerfile``, ``src/`` and ``tests/`` into a fresh temp dir
   (``--head``: ``git archive HEAD`` instead, with ``tests/redteam/`` overlaid from the working tree so new RT tests
   count). Every later step works on copies of that snapshot only.
2. Builds the container image from the snapshot (``IMAGE``, default ``killswitch:kabir``) and runs ``tests/redteam``
   unmutated. The baseline must pass, else the gate stops: a red baseline would kill every mutant for free
   (``--allow-red-baseline`` goes on, and then only tests that pass in the baseline can kill).
3. For each mutation below: copies the base, applies exactly one textual change (the old text must occur exactly
   ``count`` times; the file must still compile), and runs ``tests/redteam`` in the container with the mutant's
   ``src/`` and ``tests/`` mounted read-only over ``/app`` (``PYTHONPATH=/app/src``, ``--network none``, root, so the
   per-agent uid tests run). A mutant is **killed** if at least one red-team test that passed in the baseline
   fails; a **survivor** is a gap.
4. Prints a table (markdown) and writes ``mutation-gate.json`` in the scratch dir; exit 0 iff every mutant is killed.

Agent subprocesses start with a clean environment and import ``ks`` from the image's installed copy (the unmutated
base); every mutation below is in a process that does get ``PYTHONPATH`` (gateway/runtime, monitor, witness link,
operator socket, verify), so the mutant code is what runs.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import py_compile
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("IMAGE", "killswitch:kabir")


@dataclass(frozen=True)
class Mutation:
    id: str
    defence: str
    path: str
    old: str
    new: str
    count: int = 1
    """Exact number of occurrences of ``old`` (all are replaced); -1 = every occurrence, at least one."""
    more: tuple[tuple[str, str, str, int], ...] = ()
    """Further (path, old, new, count) edits that belong to the same switched-off defence."""

    def edits(self) -> tuple[tuple[str, str, str, int], ...]:
        return ((self.path, self.old, self.new, self.count), *self.more)


MUTATIONS: tuple[Mutation, ...] = (
    Mutation("M01", "epoch fence, live (gateway step 8: env.epoch != current -> deny/stale_epoch)",
             "src/ks/gateway/stub.py",
             "        if env.epoch != epoch:\n            return Reason.STALE_EPOCH\n",
             "        if False:\n            return Reason.STALE_EPOCH\n"),
    Mutation("M02", "epoch fence, audit (verify B3-49: admitted at a non-current epoch -> epoch_regression)",
             "src/ks/verify/core.py",
             "                if cur is None or env.epoch != cur:\n",
             "                if False:\n"),
    Mutation("M03", "epoch fence, audit (verify B3-35: suspended/revoked act_chain ancestor -> epoch_regression)",
             "src/ks/verify/core.py",
             "                if dead:\n",
             "                if False:\n"),
    Mutation("M04", "inv.pii_egress detector (hard alert on PII in a queued email payload)",
             "src/ks/monitor/detectors.py",
             "            if payload is not MISSING and find_pii(payload, ctx.params.pii_keys, payees):\n",
             "            if False:\n"),
    Mutation("M05", "dispatcher re-check (release phase skips a suspended/revoked author's due item)",
             "src/ks/gateway/stub.py",
             "            if self.control.agent_denial(d.item.author) is not None:\n",
             "            if False:\n"),
    Mutation("M06", "outbox provenance (unrecorded_item hold for an item not tied to the log)",
             "src/ks/gateway/outbox.py",
             "        if self._unrecorded(d):\n",
             "        if False:\n"),
    Mutation("M07", "witness ack signature check (link._ingest)",
             "src/ks/witness/link.py",
             "        if cp.sig is None or not verify_hex(self.pub or \"\", cp.sig, cp.signing_bytes()):\n",
             "        if False:\n"),
    Mutation("M08", "witness ack pushed-head check (link._ingest: (seq, head) must be what was pushed for the tick)",
             "src/ks/witness/link.py",
             "        if self._pushed.get(cp.tick) != (cp.seq, cp.head):\n",
             "        if False:\n"),
    Mutation("M09", "deny-list re-read inside the write txn (step 13, RT5)",
             "src/ks/gateway/stub.py",
             "            why = self._control_denial(env, conn_id)\n            if why is not None:  # the suspend",
             "            why = None\n            if why is not None:  # the suspend"),
    Mutation("M10", "connection deny-list (conn:<id> suspended/revoked -> deny, steps 7 and 13)",
             "src/ks/gateway/stub.py",
             "        why = c.conn_denial(conn_id)\n        if why is not None:\n            return why\n",
             "        why = None\n"),
    Mutation("M11", "SO_PEERCRED peer-uid check on the operator socket (J1)",
             "src/ks/runtime/operator.py",
             "        if uid is None or uid != self.allowed_uid:",
             "        if False:"),
    Mutation("M12", "recovery-apply staleness re-check in the apply txn (M8, every ks.recovery.recheck call in "
                    "runtime/recover.py returns None)",
             "src/ks/runtime/recover.py",
             "        from ks.recovery import recheck\n",
             "        recheck = lambda *a, **k: None  # noqa: E731  (mutant)\n", count=-1,
             more=(("src/ks/runtime/recover.py", "        from ks.recovery import apply_restore, recheck\n",
                    "        from ks.recovery import apply_restore\n"
                    "        recheck = lambda *a, **k: None  # noqa: E731  (mutant)\n", 1),)),
)


def sh(argv, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, text=True, capture_output=True, **kw)


def make_base(root: Path, head: bool) -> Path:
    base = root / "base"
    base.mkdir()
    if not head:
        for name in ("pyproject.toml", "Dockerfile"):
            shutil.copy2(REPO / name, base / name)
        ign = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
        shutil.copytree(REPO / "src", base / "src", ignore=ign)
        shutil.copytree(REPO / "tests", base / "tests", ignore=ign)
    else:
        tar = root / "head.tar"
        p = sh(["git", "-C", str(REPO), "archive", "--format=tar", "-o", str(tar), "HEAD", "pyproject.toml",
                "Dockerfile", "src", "tests"])
        if p.returncode:
            sys.exit(f"git archive failed: {p.stderr}")
        with tarfile.open(tar) as t:
            t.extractall(base, filter="data")
        tar.unlink()
        rt = base / "tests" / "redteam"
        for f in (REPO / "tests" / "redteam").iterdir():  # overlay: new / edited RT tests from the working tree
            if f.is_file() and f.suffix in (".py", ".md"):
                shutil.copy2(f, rt / f.name)
    for d, _, files in os.walk(base):  # agent uids (60001+) must read the mounted tree
        os.chmod(d, 0o755)
        for f in files:
            os.chmod(os.path.join(d, f), 0o644)
    return base


def mutate(base: Path, root: Path, m: Mutation) -> Path:
    d = root / m.id
    shutil.copytree(base, d)
    for path, old, new, count in m.edits():
        f = d / path
        text = f.read_text()
        n = text.count(old)
        if n != count and not (count == -1 and n >= 1):  # -1: every occurrence, at least one
            raise RuntimeError(f"{m.id}: expected {'>=1' if count == -1 else count} occurrence(s) of the old text in {path}, found {n}")
        f.write_text(text.replace(old, new))
        py_compile.compile(str(f), doraise=True, cfile=str(root / f"{m.id}.pyc"))
    return d


def run_redteam(tree: Path, out: Path, timeout: int) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    argv = ["docker", "run", "--rm", "--network", "none",
            "-v", f"{tree / 'src'}:/app/src:ro", "-v", f"{tree / 'tests'}:/app/tests:ro", "-v", f"{out}:/out",
            "-e", "PYTHONPATH=/app/src", "-e", "PYTHONDONTWRITEBYTECODE=1", IMAGE,
            "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rs", "tests/redteam",
            "--junitxml=/out/junit.xml"]
    t0 = time.monotonic()
    try:
        p = sh(argv, timeout=timeout)
        rc, log = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc, log = -1, f"timeout after {timeout}s\n{e.stdout or ''}"
    (out / "pytest.log").write_text(log)
    failed, skipped, total = [], [], 0
    jx = out / "junit.xml"
    if jx.exists():
        for tc in ET.parse(jx).getroot().iter("testcase"):
            total += 1
            name = f"{tc.get('classname', '').split('.')[-1]}::{tc.get('name')}"
            if tc.find("failure") is not None or tc.find("error") is not None:
                failed.append(name)
            elif tc.find("skipped") is not None:
                skipped.append(name)
    return {"rc": rc, "failed": failed, "skipped": skipped, "total": total, "secs": round(time.monotonic() - t0)}


def table(rows: list[dict]) -> str:
    out = ["| ID | Defence switched off | File | Verdict | Red-team tests that fail |", "|---|---|---|---|---|"]
    for r in rows:
        v = "killed" if r["killed"] else "SURVIVED (gap)"
        names = ", ".join(f"`{n}`" for n in r["failed"][:6]) + (f" (+{len(r['failed']) - 6} more)"
                                                                 if len(r["failed"]) > 6 else "")
        out.append(f"| {r['id']} | {r['defence']} | `{r['path']}` | {v} | {names or '-'} |")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", help="comma-separated mutation ids")
    ap.add_argument("--jobs", type=int, default=3, help="containers in parallel (default 3)")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per container run")
    ap.add_argument("--head", action="store_true", help="snapshot HEAD (+ working-tree tests/redteam), not the "
                                                        "working tree")
    ap.add_argument("--allow-red-baseline", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep the scratch dir")
    ap.add_argument("--no-build", action="store_true", help="reuse IMAGE as is")
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    muts = [m for m in MUTATIONS if not a.only or m.id in a.only.split(",")]
    if a.list:
        for m in muts:
            print(f"{m.id}  {m.path}  {m.defence}")
        return 0
    root = Path(tempfile.mkdtemp(prefix="ks-mutgate-"))
    print(f"scratch: {root}  image: {IMAGE}", flush=True)
    try:
        base = make_base(root, a.head)
        for m in muts:  # fail fast on a stale mutation before any container time is spent
            mutate(base, root, m)
            shutil.rmtree(root / m.id)
        if not a.no_build:
            p = sh(["docker", "build", "-q", "-t", IMAGE, str(base)])
            if p.returncode:
                print(p.stdout + p.stderr)
                return 2
        red: set[str] = set()
        if not a.skip_baseline:
            b = run_redteam(base, root / "out-baseline", a.timeout)
            red = set(b["failed"])
            print(f"baseline: rc={b['rc']} tests={b['total']} failed={len(b['failed'])} skipped={len(b['skipped'])} "
                  f"({b['secs']}s)", flush=True)
            if not b["total"] or ((b["rc"] != 0 or b["failed"]) and not a.allow_red_baseline):
                print("baseline is not green; stopping:", b["failed"][:10])
                print((root / "out-baseline" / "pytest.log").read_text()[-3000:])
                return 2

        def one(m: Mutation) -> dict:
            r = run_redteam(mutate(base, root, m), root / f"out-{m.id}", a.timeout)
            r["failed"] = [n for n in r["failed"] if n not in red]
            killed = bool(r["failed"])  # a timeout or crash without a newly failing test is not a kill
            print(f"{m.id}: {'killed' if killed else 'SURVIVED'} rc={r['rc']} failed={len(r['failed'])} "
                  f"({r['secs']}s)", flush=True)
            return {"id": m.id, "defence": m.defence, "path": m.path, "killed": killed, **r}

        with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
            rows = sorted(ex.map(one, muts), key=lambda r: r["id"])
        (root / "mutation-gate.json").write_text(json.dumps(rows, indent=2))
        print()
        print(table(rows))
        surv = [r["id"] for r in rows if not r["killed"]]
        print(f"\n{len(rows) - len(surv)}/{len(rows)} killed" + (f"; SURVIVORS: {', '.join(surv)}" if surv else ""))
        return 1 if surv else 0
    finally:
        if not a.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

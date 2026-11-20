"""RT2 key theft (fresh keys): a rogue agent loots env, fds, readable files and other processes' /proc entries;
the harness scans the loot for every private key the run made (test-only capture of the KeyStore; the witness key
is made in the witness process and never leaves it, E4).

THREAT-MODEL claim defended: private keys are generated in memory per run and never written to disk; gateway,
witness and signer are non-dumpable and the agent runs under its own uid, so an agent cannot read a key.
"""

from __future__ import annotations

import base64
import errno

import pytest

from ks.contracts import RunDir

from .conftest import NEEDS_UIDS, inproc_run

RT2 = '''
import os, base64
def _read(p, n=65536):
    try:
        with open(p, "rb") as f:
            return base64.b64encode(f.read(n)).decode()
    except OSError as e:
        return {"errno": e.errno}
def on_start(ctx):
    ctx.dump({"env": dict(os.environ), "uid": os.getuid(), "euid": os.geteuid()})
    fds = {}
    for fd in os.listdir("/proc/self/fd"):
        try:
            fds[fd] = os.readlink(f"/proc/self/fd/{fd}")
        except OSError as e:
            fds[fd] = e.errno
    ctx.dump({"fds": fds})
    for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
        if int(pid) == os.getpid():
            continue
        loot = {"pid": int(pid)}
        for f in ("environ", "cmdline", "maps"):
            loot[f] = _read(f"/proc/{pid}/{f}", 4096)
        try:
            with open(f"/proc/{pid}/mem", "rb") as m:
                m.read(1)
            loot["mem"] = "OK"
        except OSError as e:
            loot["mem"] = {"errno": e.errno}
        ctx.dump(loot)
    n = 0
    for root in ("/tmp", "/run", "/root", "/home", "/var/tmp"):
        for d, subs, files in os.walk(root, onerror=lambda e: None):
            for name in files:
                v = _read(os.path.join(d, name), 16384)
                if isinstance(v, str):
                    ctx.dump({"file": os.path.join(d, name), "b64": v})
                    n += 1
            if n > 400:
                break
    ctx.report(kind="done")
def on_tick(ctx, t):
    pass
'''


@NEEDS_UIDS
def test_rt2_no_private_key_reaches_the_rogue(base):
    out = base / "rt2"
    res, keys = inproc_run(out, rogue=RT2, ticks=4)
    assert RunDir(out).config().key_mode == "fresh"
    text = (out / "rogue.jsonl").read_text()
    assert '"kind":"done"' in text, "rogue loot incomplete (cap or crash): the scan would prove nothing"
    privs = {p: keys.private(p).private_bytes_raw() for p in keys._keys}  # noqa: SLF001 - test-only capture
    assert len(privs) >= 14  # gateway, monitor, operator, recovery + 10 agents
    import json
    blobs = [text]
    for line in text.splitlines():
        e = json.loads(line)
        for v in (e.get("loot") or {}).values() if isinstance(e.get("loot"), dict) else ():
            if isinstance(v, str):
                try:
                    blobs.append(base64.b64decode(v, validate=True).hex())
                except ValueError:
                    pass
    for p, raw in privs.items():
        for form in (raw.hex(), base64.b64encode(raw).decode()):
            assert not any(form in b for b in blobs), f"private key of {p} found in rogue loot"
    assert "PRIVATE KEY" not in text
    # the gateway (this process, root, non-dumpable) and the witness are unreadable from the agent uid
    import os
    for line in text.splitlines():
        loot = json.loads(line).get("loot") or {}
        if isinstance(loot, dict) and loot.get("pid") == os.getpid():
            assert isinstance(loot["environ"], dict) and loot["environ"]["errno"] in (errno.EACCES, errno.EPERM)
            assert isinstance(loot["mem"], dict)
    euid = [json.loads(l)["loot"]["euid"] for l in text.splitlines() if '"euid"' in l][0]
    assert euid not in (0, os.geteuid())

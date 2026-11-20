"""RT3b sibling hijack: a rogue in slot docs tries ptrace, pidfd_getfd and process_vm_readv on crm's process to
take its gateway socket or signer handle.

THREAT-MODEL claim defended: per-agent attribution holds only with per-agent uids and non-dumpable agents (ADR-00);
cross-uid ptrace/pidfd_getfd/process_vm_readv are EPERM, so no action is attributed to crm that crm did not send.
"""

from __future__ import annotations

import errno

from ks.contracts import RunDir

from .conftest import NEEDS_UIDS, world_run

RT3B = '''
import ctypes, os
l = ctypes.CDLL(None, use_errno=True)
def _crm():
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\\0")
            except OSError:
                continue
            if b"--agent" in cmd and cmd[cmd.index(b"--agent") + 1] == b"crm":
                return int(p)
def on_start(ctx):
    pid = _crm()
    ctx.report(kind="target", pid=pid)
    if pid is None:
        return
    r = l.ptrace(16, pid, 0, 0)
    ctx.report(kind="ptrace", errno=0 if r == 0 else ctypes.get_errno())
    pfd = l.syscall(434, pid, 0)
    if pfd < 0:
        ctx.report(kind="getfd", errno=ctypes.get_errno(), stage="pidfd_open")
    else:
        errs = set()
        for fd in range(3, 16):
            g = l.syscall(438, pfd, fd, 0)
            errs.add(0 if g >= 0 else ctypes.get_errno())
        ctx.report(kind="getfd", errno=sorted(errs)[-1] if 0 not in errs else 0, all=sorted(errs))
    class iov(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
    buf = ctypes.create_string_buffer(16)
    local, remote = iov(ctypes.cast(buf, ctypes.c_void_p), 16), iov(0x400000, 16)
    n = l.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    ctx.report(kind="vm_read", errno=0 if n >= 0 else ctypes.get_errno())
def on_tick(ctx, t):
    pass
'''


@NEEDS_UIDS
def test_rt3b_cross_uid_hijack_is_eperm(base):
    run = world_run(base, "rt3b", rogue=RT3B, ticks=6)
    assert RunDir(run.dir).config().isolation == "per_agent_uid"
    log = run.rogue_log()
    assert [e for e in log if e["kind"] == "target" and e["pid"]], log
    tries = [e for e in log if e["kind"] in ("ptrace", "getfd", "vm_read")]
    assert {e["kind"] for e in tries} == {"ptrace", "getfd", "vm_read"}, log
    assert all(e["errno"] == errno.EPERM for e in tries), tries
    sent = {e.get("hash") for e in run.rogue_log(kind="sent")}
    assert not [r for r in run.records() if r.envelope_hash in sent and r.attributed_agent == "crm"]

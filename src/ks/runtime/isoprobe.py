"""Isolation probe (B3-10 acceptance, red-team RT3): started through ``spawn.BOOT`` under an agent uid exactly like
an agent, it tries ``PTRACE_ATTACH`` on each target pid and reports the errno name per pid as one canonical line
on its socket. ``EPERM`` everywhere is the pass. Linux only (on other platforms it reports ``unsupported``).

    main([SOCK_FD, PID, PID, ...])

Not used by ``ks run``; tests spawn it next to real agent and witness processes.
"""

from __future__ import annotations

import ctypes
import errno
import os
import socket
import sys

from ks.contracts import canonical

PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def attach_errno(pid: int) -> str:
    """``EPERM`` if the kernel refuses; ``attached`` if it let us in (then detached again: a failure)."""
    if sys.platform != "linux":
        return "unsupported"
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    if libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1:
        return errno.errorcode.get(ctypes.get_errno(), "E?")
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    libc.ptrace(PTRACE_DETACH, pid, None, None)
    return "attached"


def main(argv: list[str]) -> int:
    sock = socket.socket(fileno=int(argv[0]))
    res = {"uid": os.getuid(), "results": {p: attach_errno(int(p)) for p in argv[1:]}}
    sock.sendall(canonical.dumps_line(res))
    sock.close()
    return 0

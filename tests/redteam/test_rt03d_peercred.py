"""RT3d (S4-21): the SO_PEERCRED check holds by itself when the operator directory's permissions do not.

THREAT-MODEL B5: "Root-only dir plus `SO_PEERCRED` uid 0; the only path for `ks contain` and `ks recover --apply`".
These are two layers. RT3c leg (d) shows that an agent uid cannot even traverse the 0700 directory, so it never
reaches the peer-uid check. The mutation gate (M11) showed that switching ``SO_PEERCRED`` off survived the whole red
team. This module removes the first layer on purpose: while the run is paused, the harness (root) opens the
operator directory to 0711 and the socket to 0666, as a mis-deployed socket directory would be. A process running
as the ``docs`` agent's uid then connects and asks for ``suspend agent:billing``. Claim: the kernel-reported peer uid
is refused. Nothing is read from that peer, no Control is applied, billing stays active, and the run summary counts
the refused peer.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from ks.contracts import ControlOp
from ks.runtime.spawn import agent_uid

from .conftest import AGENTS, NEEDS_UIDS, assert_global, world_run

DOCS_UID = agent_uid(AGENTS.index("docs"))  # the uid a compromised docs agent runs as
CHILD = r'''
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print(json.dumps({"connected": False, "errno": e.errno}))
    sys.exit(0)
got, err = b"", None
try:  # a refused peer is closed without a word: EOF or ECONNRESET, never a reply
    s.sendall(b'{"op":"suspend","target":"agent:billing"}\n')
    got = s.recv(4096)
except OSError as e:
    err = e.errno
print(json.dumps({"connected": True, "reply": got.decode(errors="replace"), "errno": err}))
'''


def _knock(box: list):
    def act(run_dir):
        d = run_dir / "operator"
        sock = d / "operator.sock"
        os.chmod(d, 0o711)  # layer 1 down (simulated misconfiguration): agent uids can traverse and connect
        os.chmod(sock, 0o666)
        try:
            p = subprocess.run([sys.executable, "-c", CHILD, str(sock)], user=DOCS_UID, group=DOCS_UID,
                               capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
            box.append(json.loads(p.stdout.strip().splitlines()[-1]))
        finally:
            os.chmod(sock, 0o600)
            os.chmod(d, 0o700)
        return {"ok": True}
    return act


@NEEDS_UIDS
def test_rt3d_agent_uid_refused_by_peercred_when_dir_is_open(base):
    box: list = []
    run = world_run(base, "rt3d", ticks=10, actions={4: [_knock(box), {"op": "resume"}]})
    (k,) = box
    assert k["connected"] is True, k  # layer 1 really was down: the agent uid reached the socket
    assert k["reply"] == "", k  # closed without a word
    ops = [c for r, c in run.controls() if c.issued_by == "ks.operator"]
    assert not ops, ops
    assert run.status("agent:billing") == "active"
    assert not [c for _, c in run.controls() if c.target == "agent:billing" and c.op == ControlOp.SUSPEND]
    m = re.search(r"operator socket: (\d+) refused peers", run.stdout)
    assert m and int(m.group(1)) >= 1, run.stdout[-1500:]
    assert_global(run)

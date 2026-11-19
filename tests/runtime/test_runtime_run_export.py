"""ks.runtime.run stays callable however the submodule gets imported (ishaan, B3-12 shadowing report)."""
import subprocess
import sys

import pytest

ORDERS = {
    "from_pkg_first": "from ks.runtime import run as r\nimport ks.runtime.run as m\n",
    "submodule_first": "import ks.runtime.run as m\nfrom ks.runtime import run as r\n",
    "from_submodule": "from ks.runtime.run import run as f\nimport ks.runtime as p\nr = p.run\nimport ks.runtime.run as m\n",
}

CHECK = """
import sys, types
import ks.runtime
assert callable(r) and r is ks.runtime.run is m is sys.modules['ks.runtime.run'], (r, m)
assert isinstance(m, types.ModuleType) and callable(m.run) and hasattr(m, 'WitnessLink')
seen = {}
m.run = lambda **kw: seen.update(kw) or 'ok'   # the call resolves m.run per call: patchable
assert r(seed=3) == 'ok' and ks.runtime.run(seed=4) == 'ok' and seen == {'seed': 4}
"""


@pytest.mark.parametrize("order", sorted(ORDERS))
def test_run_is_callable_in_any_import_order(order):
    code = ORDERS[order] + CHECK
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_package_import_alone_does_not_load_run_submodule():
    code = "import sys, ks.runtime\nassert 'ks.runtime.run' not in sys.modules\nimport ks.runtime.agent_template\nassert 'ks.runtime.run' not in sys.modules\n"
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_monkeypatching_the_package_attribute_still_works(monkeypatch):
    import ks.runtime
    monkeypatch.setattr("ks.runtime.run", lambda **kw: kw)
    assert ks.runtime.run(a=1) == {"a": 1}

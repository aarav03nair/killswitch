"""ks.runtime: process topology, uids, tick barrier, teardown (ADR-00). Owner: maya.

Imports are lazy so that a child process importing ``ks.runtime.agent_template`` loads only what it needs.

``ks.runtime.run`` is both the entry point and the name of the submodule that holds it. Python's import system
binds a submodule onto its package (``setattr(ks.runtime, "run", <module>)``) the first time anything imports
``ks.runtime.run``, which used to shadow the callable. To keep one stable meaning, the attribute ``run`` is always
the submodule, made callable: ``ks.runtime.run(**kw)`` and ``from ks.runtime import run; run(**kw)`` call
``ks.runtime.run.run(**kw)``, before or after any other import of the submodule, and ``import ks.runtime.run as m``
still yields the real module (so ``monkeypatch.setattr(m, ...)`` keeps working).
"""

import sys
import types

from .options import RunOptions

__all__ = ["RunOptions", "run"]

_RUN_MODULE = __name__ + ".run"


class _CallableRunModule(types.ModuleType):
    """The ``ks.runtime.run`` submodule, callable as its own ``run`` function (resolved per call: patchable)."""

    def __call__(self, *args, **kwargs):
        return self.run(*args, **kwargs)


class _Package(types.ModuleType):
    def __setattr__(self, name, value):
        if (name == "run" and isinstance(value, types.ModuleType) and value.__name__ == _RUN_MODULE
                and not isinstance(value, _CallableRunModule)):
            value.__class__ = _CallableRunModule
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _Package


def __getattr__(name):
    if name == "run":  # first access: import the submodule (lazy); the import binds it via _Package.__setattr__
        import importlib
        return importlib.import_module(_RUN_MODULE)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

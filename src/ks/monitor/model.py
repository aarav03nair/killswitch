"""Detector inputs: the records, a read-only state view, the side store and the knobs.

The monitor never receives a ``RunConfig``: everything it needs from the scenario arrives as
:class:`MonitorParams` (sensitive payee fields, windows, price rules). It therefore cannot read the
scorer-only ground truth (A3), and a test pins that with an AST guard.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ks.contracts import (AGENT_ID_RE if False else ActionClass, Decision, ObjVer, Record, SideStore, StateView,
                          WitnessCheckpoint)  # noqa: E501

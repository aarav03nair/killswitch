"""IBAN format and mod-97 checksum (ISO 13616). Pure, no I/O."""

from __future__ import annotations

import re

__all__ = ["IBAN_LENGTHS", "iban_problem", "iban_ok", "mod97"]

IBAN_LENGTHS = {
    "AE": 23, "AT": 20, "BE": 16, "CH": 21, "DE": 22, "DK": 18, "ES": 24, "FI": 18, "FR": 27, "GB": 22,
    "GR": 27, "IE": 22, "IT": 27, "LU": 20, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "SA": 24, "SE": 24,
}
"""Registry lengths for the countries the scenarios use; an unlisted country falls back to 15..34."""

_SHAPE = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$")


def mod97(iban: str) -> int:
    moved = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97


def iban_problem(value: object) -> str | None:
    """``None`` when ``value`` is a well-formed, checksum-valid IBAN, else a short reason code."""
    if not isinstance(value, str):
        return "not_a_string"
    if not _SHAPE.fullmatch(value):
        return "format"
    want = IBAN_LENGTHS.get(value[:2])
    if want is not None and len(value) != want:
        return "length"
    if mod97(value) != 1:
        return "checksum"
    return None


def iban_ok(value: object) -> bool:
    return iban_problem(value) is None

"""Sensitive-field objects on the write side (C3 B1/X1/X2, ADR-05 §1).

Each ``RunConfig.sensitive_fields`` entry ``table.field`` is its own versioned object ``table:pk.field``.
A row value never carries a sensitive key, so each datum lives in exactly one object and the row's value
hash excludes sensitive fields. Sensitivity comes only from config (no IBAN-specific code).

This module is the seam between the store and the config: :class:`FieldSchema` answers "which fields of
this table are objects of their own" and splits a full row into its row part and field parts. The read
rule (whole-row reads list the row's existing field objects) is B3-04 and builds on the same schema.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ks.contracts import RunConfig, split_obj_id

__all__ = ["FieldSchema", "SensitiveKeyError"]


class SensitiveKeyError(ValueError):
    """A row value carries a sensitive key, or a field object names a field that is not sensitive."""


class FieldSchema:
    """Which ``table.field`` entries are field objects. Immutable; build from config or a plain list."""

    def __init__(self, sensitive_fields: Iterable[str] = ()):
        by_table: dict[str, list[str]] = {}
        for entry in sensitive_fields:
            table, dot, field = entry.partition(".")
            if not dot or not table or not field:
                raise ValueError(f"sensitive field {entry!r} is not 'table.field'")
            by_table.setdefault(table, []).append(field)
        self._by_table = {t: tuple(sorted(set(fs))) for t, fs in by_table.items()}

    @classmethod
    def from_config(cls, config: RunConfig) -> FieldSchema:
        return cls(config.sensitive_fields)

    def fields_of(self, table: str) -> tuple[str, ...]:
        """Sensitive field names of ``table`` (sorted)."""
        return self._by_table.get(table, ())

    def field_objs_of(self, row_obj: str) -> tuple[str, ...]:
        """Every possible field object id of a row (existing or not), sorted by field name."""
        table, pk, field = split_obj_id(row_obj)
        if field is not None:
            raise ValueError(f"{row_obj!r} is a field object, not a row")
        return tuple(f"{table}:{pk}.{f}" for f in self.fields_of(table))

    def check_obj(self, obj: str) -> None:
        """Kabir R1 (as ``RunConfig.check_obj``): a ``.field`` suffix must name a sensitive field."""
        table, _, field = split_obj_id(obj)
        if field is not None and field not in self.fields_of(table):
            raise SensitiveKeyError(f"{obj!r}: '.{field}' is not a sensitive field of table {table!r}")

    def check_value(self, obj: str, value: Any) -> None:
        """A row value must not carry a sensitive key (each datum in exactly one object)."""
        table, _, field = split_obj_id(obj)
        if field is not None or not isinstance(value, Mapping):
            return
        bad = sorted(k for k in value if k in self.fields_of(table))
        if bad:
            raise SensitiveKeyError(f"row value of {obj!r} carries sensitive key(s) {bad}; "
                                    f"write them as field objects {table}:<pk>.<field>")

    def split(self, row_obj: str, value: Any) -> tuple[Any, dict[str, Any]]:
        """Full row -> ``(row part, {field_obj: value | None})``. Every sensitive field of the table appears
        in the second part; an absent or null field maps to ``None`` (a tombstone, X2). A ``None`` row
        (delete) maps every field to ``None``. A table without sensitive fields passes through unchanged."""
        table, _, field = split_obj_id(row_obj)
        if field is not None:
            raise ValueError(f"{row_obj!r} is a field object, not a row")
        names = self.fields_of(table)
        if value is None:
            return None, {f"{row_obj}.{f}": None for f in names}
        if not names:
            return value, {}
        if not isinstance(value, Mapping):
            raise SensitiveKeyError(f"{row_obj!r}: table {table!r} has sensitive fields, row value must be an object")
        row = {k: v for k, v in value.items() if k not in names}
        return row, {f"{row_obj}.{f}": value.get(f) for f in names}

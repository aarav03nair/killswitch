"""Base classes: every contract type is a frozen, extra-forbidding pydantic model with canonical I/O."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

from . import canonical
from .hashing import sha256_hex

__all__ = ["Value", "Document", "OMIT_DEFAULT_KEY", "additive"]

OMIT_DEFAULT_KEY = "x-ks-omit-default"
"""JSON-schema marker of an *additive* field (see :func:`additive`). ``schema_gen`` leaves it out of ``required``."""


def additive(default: Any, **kw: Any) -> Any:
    """Declare a field added in a later minor version (v1.4, B3-46). The ONE additivity rule: such a field is
    **omitted from the canonical form when it equals its default**, so every document written before the field
    existed keeps its exact bytes, hashes and signatures (old runs still verify). A non-default value is
    serialized and round-trips. Strict parse stays strict: an explicit default value in the bytes is not the
    canonical form and is rejected (:class:`~ks.contracts.canonical.NonCanonicalError`)."""
    extra = dict(kw.pop("json_schema_extra", None) or {})
    extra[OMIT_DEFAULT_KEY] = True
    return Field(default, json_schema_extra=extra, **kw)


def _omit_defaults(cls: type[BaseModel]) -> tuple[tuple[str, Any], ...]:
    cached = cls.__dict__.get("__ks_omit__")
    if cached is None:
        cached = tuple((n, f.default) for n, f in cls.model_fields.items()
                       if isinstance(f.json_schema_extra, dict) and f.json_schema_extra.get(OMIT_DEFAULT_KEY))
        setattr(cls, "__ks_omit__", cached)
    return cached


class Value(BaseModel):
    """A contract value type. Immutable; unknown fields are rejected (fail closed)."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True,
                              validate_default=True, str_strip_whitespace=False)

    @model_serializer(mode="wrap")
    def _ks_ser(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        out = handler(self)
        for name, default in _omit_defaults(type(self)):
            if getattr(self, name) == default:
                out.pop(name, None)
        return out

    def to_obj(self) -> dict[str, Any]:
        """JSON-ready dict: every field present (``None`` as null), except :func:`additive` fields at their
        default, which are omitted (applies to nested values too)."""
        return self.model_dump(mode="json")

    def __ks_canonical__(self) -> dict[str, Any]:
        return self.to_obj()

    def to_canonical(self) -> bytes:
        """Canonical ks-canon/1 bytes of the whole object."""
        return canonical.dumps(self.to_obj())

    @classmethod
    def from_obj(cls, obj: Any) -> Self:
        return cls.model_validate(obj)

    @classmethod
    def from_canonical(cls, data: bytes) -> Self:
        """Strict parse: bytes must be canonical AND equal the canonical form of the parsed model
        (so missing defaulted fields or unsorted sets are rejected, not silently fixed).
        Every failure is a :class:`~ks.contracts.canonical.CanonicalError` (validation failures are the
        subclass :class:`~ks.contracts.canonical.ContractError`)."""
        obj = canonical.loads(data)
        try:
            m = cls.model_validate(obj)
            again = m.to_canonical()
        except canonical.CanonicalError:
            raise
        except Exception as exc:  # pydantic ValidationError, RecursionError, ...
            raise canonical.ContractError(f"{cls.__name__}: {exc}") from exc
        if again != bytes(data):
            raise canonical.NonCanonicalError(f"{cls.__name__}: bytes are not this object's canonical form")
        return m


class Document(Value):
    """A top-level, independently hashed/signed contract document."""

    CONTRACT: ClassVar[str]
    DOMAIN: ClassVar[bytes]
    UNSIGNED_FIELDS: ClassVar[frozenset[str]] = frozenset()
    """Fields excluded from :meth:`signing_bytes` (the hash/signature fields themselves)."""

    def signing_bytes(self) -> bytes:
        """``DOMAIN + 0x00 + canonical(self minus UNSIGNED_FIELDS)``: sign-ready bytes."""
        obj = self.to_obj()
        for f in self.UNSIGNED_FIELDS:
            obj.pop(f, None)
        return self.DOMAIN + b"\x00" + canonical.dumps(obj)

    def content_hash(self) -> str:
        """sha256 hex of :meth:`signing_bytes`."""
        return sha256_hex(self.signing_bytes())

"""Base classes: every contract type is a frozen, extra-forbidding pydantic model with canonical I/O."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict

from . import canonical
from .hashing import sha256_hex

__all__ = ["Value", "Document"]


class Value(BaseModel):
    """A contract value type. Immutable; unknown fields are rejected (fail closed)."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True,
                              validate_default=True, str_strip_whitespace=False)

    def to_obj(self) -> dict[str, Any]:
        """JSON-ready dict (every field present, ``None`` as null)."""
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
        (so missing defaulted fields or unsorted sets are rejected, not silently fixed)."""
        m = cls.model_validate(canonical.loads(data))
        if m.to_canonical() != bytes(data):
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

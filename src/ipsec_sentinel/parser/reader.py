"""A byte reader that cannot read past its bounds.

Every parser vulnerability in this class of software is a bounds error, and IKE is a
format built almost entirely out of attacker-supplied length fields: payload lengths,
proposal lengths, transform lengths, attribute lengths, each nested inside the last.
A parser that trusts any of them is one malformed packet away from reading whatever
follows in memory, or from looping forever.

So the contract here is absolute and deliberately unforgiving:

* a read that cannot be satisfied raises :class:`TruncatedError`;
* nothing is ever zero-padded, truncated or returned partially;
* a failed read leaves the position untouched, so a caller that catches and continues
  sees a consistent reader;
* :meth:`SafeReader.sub` hands out a **bounded** child, so a nested length field can
  never reach past its own container even when the parent still holds data.

All integers are big-endian: IKE is a network protocol and a little-endian read would
transpose fields silently rather than failing.
"""

from __future__ import annotations

import struct
from typing import Final

_U16: Final = struct.Struct("!H")
_U32: Final = struct.Struct("!I")


class ParseError(Exception):
    """Base for every parse failure.

    Exists so a caller — the fuzz harness above all — can distinguish "this input was
    rejected as malformed", which is correct behaviour, from any other exception,
    which is a bug.
    """


class TruncatedError(ParseError):
    """The buffer ended before the requested read could be satisfied."""


class MalformedError(ParseError):
    """The input is structurally impossible, independent of how much of it there is."""


class SafeReader:
    """A bounded cursor over a byte buffer."""

    __slots__ = ("_data", "_end", "_position", "_start")

    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self._data = data
        self._start = start
        self._end = len(data) if end is None else end
        self._position = start

    def __repr__(self) -> str:
        return f"SafeReader(consumed={self._position - self._start}, remaining={self.remaining()})"

    def remaining(self) -> int:
        """Bytes left inside this reader's window."""
        return self._end - self._position

    def tell_relative(self) -> int:
        """Bytes consumed within this reader's window.

        Relative rather than absolute so a sub-reader reports offsets inside its own
        container, which is what a finding's evidence should cite.
        """
        return self._position - self._start

    def at_end(self) -> bool:
        return self.remaining() == 0

    def _require(self, count: int) -> int:
        """Validate a read of ``count`` bytes and return its start offset.

        Raises before mutating anything, which is what keeps the position consistent
        after a caught failure.
        """
        if count < 0:
            raise MalformedError(f"cannot read a negative length ({count})")
        if count > self.remaining():
            raise TruncatedError(f"needed {count} bytes but only {self.remaining()} remain")
        return self._position

    def u8(self) -> int:
        offset = self._require(1)
        self._position += 1
        return self._data[offset]

    def u16(self) -> int:
        offset = self._require(2)
        self._position += 2
        return int(_U16.unpack_from(self._data, offset)[0])

    def u32(self) -> int:
        offset = self._require(4)
        self._position += 4
        return int(_U32.unpack_from(self._data, offset)[0])

    def read_bytes(self, count: int) -> bytes:
        """Read exactly ``count`` bytes.

        Named ``read_bytes`` rather than ``bytes`` so it does not shadow the builtin
        inside a module that handles raw buffers constantly.
        """
        offset = self._require(count)
        self._position += count
        return self._data[offset : offset + count]

    def peek(self, count: int) -> bytes:
        """Look ahead without consuming."""
        offset = self._require(count)
        return self._data[offset : offset + count]

    def sub(self, count: int) -> SafeReader:
        """Carve off a bounded child reader and advance past it.

        The child's window is fixed at ``count`` bytes. It cannot see beyond that even
        though the underlying buffer continues — which is precisely what stops an
        oversized nested length field from walking into its siblings.
        """
        offset = self._require(count)
        self._position += count
        return SafeReader(self._data, start=offset, end=offset + count)

    def rest(self) -> bytes:
        """Consume and return everything left in this window."""
        return self.read_bytes(self.remaining())

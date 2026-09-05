"""Tests for the bounds-safe byte reader (build plan Step 4.1).

Every parser vulnerability in this class of software is a bounds error, so the
contract is absolute: a read that cannot be satisfied raises, and nothing else ever
happens. No partial results, no zero padding, no silent truncation.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ipsec_sentinel.parser.reader import (
    MalformedError,
    ParseError,
    SafeReader,
    TruncatedError,
)


class TestScalarReads:
    def test_u8(self) -> None:
        assert SafeReader(b"\x2a").u8() == 42

    def test_u16_is_big_endian(self) -> None:
        """Network byte order. A little-endian read would silently transpose fields."""
        assert SafeReader(b"\x01\x02").u16() == 0x0102

    def test_u32_is_big_endian(self) -> None:
        assert SafeReader(b"\x01\x02\x03\x04").u32() == 0x01020304

    def test_reads_advance_the_position(self) -> None:
        reader = SafeReader(b"\x01\x02\x03\x04\x05\x06\x07")
        assert reader.u8() == 1
        assert reader.u16() == 0x0203
        assert reader.u32() == 0x04050607
        assert reader.remaining() == 0

    def test_bytes_returns_exactly_the_requested_length(self) -> None:
        assert SafeReader(b"abcdef").read_bytes(3) == b"abc"

    def test_zero_length_read_is_allowed(self) -> None:
        assert SafeReader(b"").read_bytes(0) == b""


class TestTruncation:
    @pytest.mark.parametrize(
        ("data", "method"),
        [
            (b"", "u8"),
            (b"\x01", "u16"),
            (b"\x01\x02\x03", "u32"),
            (b"", "u32"),
        ],
    )
    def test_reading_past_the_end_raises(self, data: bytes, method: str) -> None:
        with pytest.raises(TruncatedError):
            getattr(SafeReader(data), method)()

    def test_bytes_past_the_end_raises(self) -> None:
        with pytest.raises(TruncatedError):
            SafeReader(b"abc").read_bytes(4)

    def test_a_failed_read_does_not_advance_the_position(self) -> None:
        """A caller that catches and retries must not observe a corrupted position."""
        reader = SafeReader(b"\x01")
        with pytest.raises(TruncatedError):
            reader.u32()
        assert reader.remaining() == 1
        assert reader.u8() == 1

    def test_negative_length_is_rejected(self) -> None:
        with pytest.raises(MalformedError):
            SafeReader(b"abcdef").read_bytes(-1)

    def test_truncation_reports_what_was_wanted_and_what_was_left(self) -> None:
        with pytest.raises(TruncatedError, match=r"needed 4 bytes but only 1 remain"):
            SafeReader(b"\x01").u32()


class TestSubReaders:
    def test_sub_reads_only_its_own_window(self) -> None:
        reader = SafeReader(b"\x01\x02\x03\x04\x05\x06")
        child = reader.sub(2)
        assert child.read_bytes(2) == b"\x01\x02"
        assert child.remaining() == 0

    def test_sub_cannot_read_beyond_its_bound_even_though_the_parent_has_more(self) -> None:
        """The guard that stops a nested length field escaping its container."""
        reader = SafeReader(b"\x01\x02\x03\x04\x05\x06")
        child = reader.sub(2)
        with pytest.raises(TruncatedError):
            child.u32()
        assert reader.remaining() == 4

    def test_sub_advances_the_parent(self) -> None:
        reader = SafeReader(b"\x01\x02\x03\x04")
        reader.sub(3)
        assert reader.remaining() == 1
        assert reader.u8() == 4

    def test_sub_longer_than_the_parent_raises(self) -> None:
        with pytest.raises(TruncatedError):
            SafeReader(b"\x01\x02").sub(3)

    def test_nested_subs_narrow_monotonically(self) -> None:
        reader = SafeReader(bytes(range(20)))
        outer = reader.sub(10)
        inner = outer.sub(4)
        assert inner.remaining() == 4
        with pytest.raises(TruncatedError):
            inner.read_bytes(5)

    def test_sub_of_zero_is_empty(self) -> None:
        reader = SafeReader(b"\x01\x02")
        assert reader.sub(0).remaining() == 0
        assert reader.remaining() == 2


class TestIntrospection:
    def test_remaining_counts_down(self) -> None:
        reader = SafeReader(b"abcd")
        assert reader.remaining() == 4
        reader.u16()
        assert reader.remaining() == 2

    def test_at_end(self) -> None:
        reader = SafeReader(b"a")
        assert reader.at_end() is False
        reader.u8()
        assert reader.at_end() is True

    def test_peek_does_not_advance(self) -> None:
        reader = SafeReader(b"\x01\x02")
        assert reader.peek(2) == b"\x01\x02"
        assert reader.remaining() == 2

    def test_peek_past_the_end_raises(self) -> None:
        with pytest.raises(TruncatedError):
            SafeReader(b"\x01").peek(2)

    def test_exceptions_share_a_base(self) -> None:
        """One except clause must be able to catch every parse failure."""
        assert issubclass(TruncatedError, ParseError)
        assert issubclass(MalformedError, ParseError)


class TestPropertyBased:
    """The contract under arbitrary input, which is where bounds bugs actually live."""

    @given(data=st.binary(min_size=0, max_size=512), n=st.integers(min_value=0, max_value=600))
    def test_read_bytes_returns_the_exact_length_or_raises(self, data: bytes, n: int) -> None:
        reader = SafeReader(data)
        try:
            out = reader.read_bytes(n)
        except TruncatedError:
            assert n > len(data)
        else:
            assert len(out) == n

    @given(
        data=st.binary(min_size=0, max_size=256),
        ops=st.lists(st.sampled_from(["u8", "u16", "u32"]), max_size=40),
    )
    def test_arbitrary_read_sequences_raise_only_truncated(
        self, data: bytes, ops: list[str]
    ) -> None:
        """Any failure must be TruncatedError; anything else is an unhandled bug."""
        reader = SafeReader(data)
        consumed = 0
        widths = {"u8": 1, "u16": 2, "u32": 4}
        for op in ops:
            try:
                value = getattr(reader, op)()
            except TruncatedError:
                assert consumed + widths[op] > len(data)
                break
            else:
                consumed += widths[op]
                assert 0 <= value < 256 ** widths[op]
        assert reader.remaining() == len(data) - consumed

    @given(data=st.binary(min_size=0, max_size=256), n=st.integers(min_value=0, max_value=300))
    def test_a_sub_reader_never_escapes_its_window(self, data: bytes, n: int) -> None:
        reader = SafeReader(data)
        try:
            child = reader.sub(n)
        except TruncatedError:
            assert n > len(data)
            return
        assert child.remaining() == n
        assert child.read_bytes(n) == data[:n]
        with pytest.raises(TruncatedError):
            child.u8()

    @given(data=st.binary(min_size=0, max_size=256))
    def test_reading_everything_then_one_more_always_raises(self, data: bytes) -> None:
        reader = SafeReader(data)
        assert reader.read_bytes(len(data)) == data
        with pytest.raises(TruncatedError):
            reader.u8()

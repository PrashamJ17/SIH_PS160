"""Tests for the payload chain walker (build plan Step 4.3).

An IKE message is a linked list whose every link length is attacker-supplied. The
walker must terminate on any input at all — a parser that hangs on a hostile packet is
a denial-of-service vector, not merely a bug.
"""

from __future__ import annotations

import struct

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ipsec_sentinel.parser.ike import MAX_PAYLOAD_CHAIN, walk_payloads
from ipsec_sentinel.parser.reader import SafeReader

PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40


def payload(next_type: int, body: bytes, critical: bool = False) -> bytes:
    return struct.pack("!BBH", next_type, 0x80 if critical else 0, 4 + len(body)) + body


class TestWellFormedChains:
    def test_three_chained_payloads_yield_three_items_in_order(self) -> None:
        chain = (
            payload(PAYLOAD_KE, b"\xaa" * 8)
            + payload(PAYLOAD_NONCE, b"\xbb" * 12)
            + payload(PAYLOAD_NONE, b"\xcc" * 4)
        )
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert [p.payload_type for p in result.payloads] == [PAYLOAD_SA, PAYLOAD_KE, PAYLOAD_NONCE]
        assert result.errors == []

    def test_bodies_are_extracted_without_the_header(self) -> None:
        result = walk_payloads(SafeReader(payload(PAYLOAD_NONE, b"\xaa" * 8)), PAYLOAD_SA)
        assert result.payloads[0].body == b"\xaa" * 8
        assert result.payloads[0].length == 12

    def test_the_chain_is_iterable_directly(self) -> None:
        chain = payload(PAYLOAD_KE, b"\x01") + payload(PAYLOAD_NONE, b"\x02")
        assert len(list(walk_payloads(SafeReader(chain), PAYLOAD_SA))) == 2

    def test_payload_names_are_resolved(self) -> None:
        result = walk_payloads(SafeReader(payload(PAYLOAD_NONE, b"")), PAYLOAD_SA)
        assert result.payloads[0].payload_type_name == "SA"

    def test_an_unknown_payload_type_is_marked_not_dropped(self) -> None:
        result = walk_payloads(SafeReader(payload(PAYLOAD_NONE, b"")), 200)
        assert "UNKNOWN" in result.payloads[0].payload_type_name
        assert result.payloads[0].payload_type == 200

    def test_the_critical_bit_is_decoded(self) -> None:
        chain = payload(PAYLOAD_NONE, b"\x01", critical=True)
        assert walk_payloads(SafeReader(chain), PAYLOAD_SA).payloads[0].critical is True

    def test_a_chain_that_ends_immediately_yields_nothing(self) -> None:
        result = walk_payloads(SafeReader(b""), PAYLOAD_NONE)
        assert result.payloads == []
        assert result.errors == []

    def test_offsets_are_recorded_for_evidence(self) -> None:
        """Findings cite byte offsets; they have to come from somewhere."""
        chain = payload(PAYLOAD_KE, b"\xaa" * 8) + payload(PAYLOAD_NONE, b"\xbb" * 4)
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert [p.offset for p in result.payloads] == [0, 12]


class TestGuards:
    def test_a_zero_length_payload_does_not_loop_forever(self) -> None:
        """The classic infinite loop: a length that never advances the cursor."""
        chain = struct.pack("!BBH", PAYLOAD_KE, 0, 0) * 50
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert any("length" in e for e in result.errors)
        assert len(result.payloads) <= 1

    def test_a_payload_shorter_than_its_own_header_is_rejected(self) -> None:
        for declared in (0, 1, 2, 3):
            chain = struct.pack("!BBH", PAYLOAD_NONE, 0, declared)
            result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
            assert result.errors, f"declared length {declared} was accepted"

    def test_a_chain_longer_than_the_guard_limit_stops(self) -> None:
        """A self-referencing chain must terminate within the guard, not run on."""
        chain = payload(PAYLOAD_SA, b"\x00") * (MAX_PAYLOAD_CHAIN + 40)
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert len(result.payloads) <= MAX_PAYLOAD_CHAIN
        assert any("chain" in e.lower() for e in result.errors)

    def test_a_payload_claiming_more_than_remains_is_rejected(self) -> None:
        chain = struct.pack("!BBH", PAYLOAD_NONE, 0, 400) + b"\xaa" * 8
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert result.errors
        assert result.truncated is True

    def test_a_partial_payload_header_is_rejected(self) -> None:
        result = walk_payloads(SafeReader(b"\x00\x00"), PAYLOAD_SA)
        assert result.errors
        assert result.payloads == []

    def test_errors_do_not_discard_payloads_already_read(self) -> None:
        """A truncated tail must not cost the proposals already parsed."""
        chain = payload(PAYLOAD_KE, b"\xaa" * 8) + struct.pack("!BBH", PAYLOAD_NONE, 0, 999)
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert len(result.payloads) == 1
        assert result.errors


class TestTermination:
    """Non-negotiable: the walker terminates on every input, and never raises."""

    @settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
    @given(data=st.binary(min_size=0, max_size=1024), first=st.integers(0, 255))
    def test_arbitrary_bytes_always_terminate_without_an_unexpected_exception(
        self, data: bytes, first: int
    ) -> None:
        result = walk_payloads(SafeReader(data), first)
        assert len(result.payloads) <= MAX_PAYLOAD_CHAIN
        assert isinstance(result.errors, list)

    @settings(max_examples=200)
    @given(data=st.binary(min_size=0, max_size=256))
    def test_the_walker_never_consumes_more_than_it_was_given(self, data: bytes) -> None:
        reader = SafeReader(data)
        result = walk_payloads(reader, PAYLOAD_SA)
        assert sum(p.length for p in result.payloads) <= len(data)

    @settings(max_examples=200)
    @given(count=st.integers(min_value=1, max_value=300))
    def test_a_long_valid_chain_is_capped_by_the_guard(self, count: int) -> None:
        chain = payload(PAYLOAD_SA, b"\x00") * count
        result = walk_payloads(SafeReader(chain), PAYLOAD_SA)
        assert len(result.payloads) <= MAX_PAYLOAD_CHAIN

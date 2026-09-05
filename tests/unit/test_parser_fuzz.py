"""Prove the parser cannot be crashed or hung by the traffic it inspects.

Build plan Step 4.9, and one of the four steps the brief marks uncuttable. The reason
is not academic. This parser is pointed at captures from networks under attack, and an
attacker who can reach a gateway can put arbitrary bytes on UDP 500. A parser that
raises an unexpected exception on those bytes takes the analysis down; one that loops
takes the analyst's afternoon. Either way the tool fails at precisely the moment it
was bought for.

The contract under test is narrow and total: for **any** input, ``parse_ike_message``
either returns a result or raises ``TruncatedError`` or ``MalformedError``. Anything
else — an IndexError, a MemoryError, a struct.error, a hang — is a bug.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ipsec_sentinel.parser.message import parse_ike_message
from ipsec_sentinel.parser.reader import MalformedError, TruncatedError
from tests.fixtures.builders import (
    build_ikev1_aggressive,
    build_multi_proposal_ike_sa_init,
    build_strong_ike_sa_init,
    build_weak_ike_sa_init,
)

# The plan's limit. Generous by three orders of magnitude for a message that is at
# most a few kilobytes, which is the point: anything approaching it is a hang.
TIME_LIMIT_S = 1.0

RANDOM_INPUT_COUNT = 10_000

VALID_FIXTURES: list[Callable[[], bytes]] = [
    build_strong_ike_sa_init,
    build_weak_ike_sa_init,
    build_multi_proposal_ike_sa_init,
    build_ikev1_aggressive,
]


def parse_or_fail(data: bytes) -> None:
    """Parse, allowing only the parser's own two errors, and time the attempt."""
    started = time.perf_counter()
    try:
        parse_ike_message(data)
    except (TruncatedError, MalformedError):
        pass
    except Exception as exc:
        raise AssertionError(
            f"unexpected {type(exc).__name__}: {exc}\ninput ({len(data)} bytes): {data[:96].hex()}"
        ) from exc
    elapsed = time.perf_counter() - started
    assert elapsed < TIME_LIMIT_S, (
        f"parsing took {elapsed:.3f}s, over the {TIME_LIMIT_S}s limit, on "
        f"{len(data)} bytes: {data[:96].hex()}"
    )


class TestRandomInput:
    def test_ten_thousand_random_inputs_produce_no_unexpected_exceptions(self) -> None:
        """The plan's headline acceptance criterion.

        Seeded so a failure is reproducible: a fuzz finding that cannot be replayed is
        a rumour rather than a bug report.
        """
        rng = random.Random(20260905)
        for _ in range(RANDOM_INPUT_COUNT):
            size = rng.choice([0, 1, 4, 27, 28, 29, 64, 256, 1024, 4096])
            parse_or_fail(bytes(rng.getrandbits(8) for _ in range(size)))

    def test_random_input_that_looks_like_a_header_is_also_safe(self) -> None:
        """Wholly random bytes rarely survive header validation.

        Most random inputs are rejected at the length check and never reach the
        payload walker, so the interesting region has to be aimed at deliberately: a
        plausible header with a random body is what actually exercises the chain.
        """
        rng = random.Random(1)
        for _ in range(RANDOM_INPUT_COUNT // 10):
            body_length = rng.randrange(0, 512)
            header = (
                bytes(rng.getrandbits(8) for _ in range(16))
                + bytes([rng.randrange(0, 60)])
                + bytes([rng.choice([0x10, 0x20])])
                + bytes([rng.randrange(0, 50)])
                + bytes([rng.getrandbits(8)])
                + rng.randbytes(4)
                + (28 + body_length).to_bytes(4, "big")
            )
            parse_or_fail(header + rng.randbytes(body_length))

    @given(st.binary(min_size=0, max_size=4096))
    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_hypothesis_finds_no_unexpected_exception(self, data: bytes) -> None:
        parse_or_fail(data)


class TestStructuredMutation:
    """Mutations of valid messages, which reach far deeper than random bytes."""

    def test_single_byte_flips_are_survived(self) -> None:
        rng = random.Random(7)
        for build in VALID_FIXTURES:
            original = build()
            for _ in range(500):
                mutated = bytearray(original)
                mutated[rng.randrange(len(mutated))] = rng.getrandbits(8)
                parse_or_fail(bytes(mutated))

    def test_truncation_at_every_offset_is_survived(self) -> None:
        """Every prefix of a valid message, which is what a snaplen cut produces."""
        for build in VALID_FIXTURES:
            original = build()
            for cut in range(len(original) + 1):
                parse_or_fail(original[:cut])

    def test_inflated_length_fields_are_survived(self) -> None:
        """A length claiming more than exists is the classic overread trigger."""
        for build in VALID_FIXTURES:
            original = bytearray(build())
            for claimed in (0, 1, 27, 28, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF):
                mutated = bytearray(original)
                mutated[24:28] = claimed.to_bytes(4, "big")
                parse_or_fail(bytes(mutated))

    def test_every_payload_length_field_inflated_is_survived(self) -> None:
        """Walk the message inflating each 16-bit word in turn.

        Crude, and that is deliberate: it hits the payload and transform length fields
        without the test needing to know where they are, so it keeps working as the
        parser grows.
        """
        for build in VALID_FIXTURES:
            original = build()
            for offset in range(28, len(original) - 1):
                mutated = bytearray(original)
                mutated[offset : offset + 2] = b"\xff\xff"
                parse_or_fail(bytes(mutated))

    def test_zeroed_length_fields_are_survived(self) -> None:
        """A zero length is the classic infinite-loop trigger: the cursor never moves."""
        for build in VALID_FIXTURES:
            original = build()
            for offset in range(28, len(original) - 1):
                mutated = bytearray(original)
                mutated[offset : offset + 2] = b"\x00\x00"
                parse_or_fail(bytes(mutated))

    def test_random_splices_of_two_valid_messages_are_survived(self) -> None:
        rng = random.Random(11)
        first, second = build_strong_ike_sa_init(), build_ikev1_aggressive()
        for _ in range(1000):
            cut = rng.randrange(len(first))
            parse_or_fail(first[:cut] + second[cut % len(second) :])


class TestPathologicalStructures:
    """Inputs shaped specifically to defeat a naive parser."""

    def test_a_self_referencing_payload_chain_terminates(self) -> None:
        """A payload whose next type points back at itself, forever."""
        header = build_strong_ike_sa_init()[:28]
        # 4-byte payload header: next payload 33, no flags, length 4 (header only).
        loop = b"\x21\x00\x00\x04" * 200
        message = bytearray(header + loop)
        message[16] = 33
        message[24:28] = len(message).to_bytes(4, "big")
        parse_or_fail(bytes(message))

    def test_a_deeply_nested_proposal_list_terminates(self) -> None:
        header = bytearray(build_strong_ike_sa_init()[:28])
        header[16] = 33
        # SA payload whose body is a long run of minimal proposals.
        body = b"\x02\x00\x00\x08\x01\x01\x00\x00" * 500
        payload = b"\x00\x00" + (4 + len(body)).to_bytes(2, "big") + body
        message = bytearray(bytes(header) + payload)
        message[24:28] = len(message).to_bytes(4, "big")
        parse_or_fail(bytes(message))

    def test_a_message_of_only_zeros_terminates(self) -> None:
        for size in (28, 64, 4096):
            parse_or_fail(b"\x00" * size)

    def test_a_message_of_only_ones_terminates(self) -> None:
        for size in (28, 64, 4096):
            parse_or_fail(b"\xff" * size)

    @pytest.mark.parametrize("size", [0, 1, 27, 28, 29])
    def test_boundary_sizes_around_the_header(self, size: int) -> None:
        parse_or_fail(b"\x11" * size)


class TestPayloadTypeCoverage:
    """Random bytes almost never name a payload type the parser handles.

    Pure random input therefore exercises the chain walker and stops there: measured,
    zero of ten thousand random inputs ever produced a parsed payload. The generators
    below aim at the SA, KE, notify and vendor ID parsers deliberately, because that
    is where the parsing actually happens and so where a crash would actually live.
    """

    @staticmethod
    def _framed(payload_type: int, body: bytes) -> bytes:
        header = bytearray(build_strong_ike_sa_init()[:28])
        header[16] = payload_type
        payload = b"\x00\x00" + (4 + len(body)).to_bytes(2, "big") + body
        message = bytearray(bytes(header) + payload)
        message[24:28] = len(message).to_bytes(4, "big")
        return bytes(message)

    @pytest.mark.parametrize("payload_type", list(range(0, 60)))
    def test_every_payload_type_with_a_random_body_is_survived(self, payload_type: int) -> None:
        rng = random.Random(payload_type)
        for _ in range(200):
            parse_or_fail(self._framed(payload_type, rng.randbytes(rng.randrange(0, 256))))

    def test_random_sa_payload_bodies_are_survived(self) -> None:
        """Aimed straight at the proposal, transform and attribute parsers."""
        rng = random.Random(99)
        for _ in range(2000):
            parse_or_fail(self._framed(33, rng.randbytes(rng.randrange(0, 512))))

    def test_sa_bodies_with_plausible_proposal_framing_are_survived(self) -> None:
        """Random bytes rarely produce a valid proposal header; these always do."""
        rng = random.Random(123)
        for _ in range(2000):
            body = b""
            for _ in range(rng.randrange(1, 6)):
                spi_size = rng.randrange(0, 8)
                transforms = rng.randbytes(rng.randrange(0, 64))
                inner = (
                    bytes([rng.randrange(0, 3), rng.randrange(0, 5), spi_size, rng.randrange(0, 8)])
                    + rng.randbytes(spi_size)
                    + transforms
                )
                body += bytes([rng.choice([0, 2]), 0]) + (4 + len(inner)).to_bytes(2, "big") + inner
            parse_or_fail(self._framed(33, body))

    def test_random_ikev1_sa_bodies_are_survived(self) -> None:
        """The IKEv1 SA path has its own framing: DOI, Situation, then proposals."""
        rng = random.Random(321)
        for _ in range(2000):
            header = bytearray(build_ikev1_aggressive()[:28])
            header[16] = 1
            body = rng.randbytes(rng.randrange(0, 256))
            payload = b"\x00\x00" + (4 + len(body)).to_bytes(2, "big") + body
            message = bytearray(bytes(header) + payload)
            message[24:28] = len(message).to_bytes(4, "big")
            parse_or_fail(bytes(message))

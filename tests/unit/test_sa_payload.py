"""Tests for proposal and SA payload parsing (build plan Step 4.5).

A real initiator message carries several proposals — it is a menu, and the responder
picks one item. Auditing only the accepted proposal would miss what the device is
willing to fall back to, which is the more useful finding: a gateway that negotiated
AES-256 today but also advertised 3DES will accept 3DES tomorrow from a peer that
offers only that.
"""

from __future__ import annotations

import struct

import pytest

from ipsec_sentinel.models import TransformType
from ipsec_sentinel.parser.ike import parse_proposal, parse_sa_payload
from ipsec_sentinel.parser.reader import MalformedError, SafeReader
from tests.fixtures.builders import (
    build_multi_proposal_ike_sa_init,
    build_strong_ike_sa_init,
    build_transform,
    build_weak_ike_sa_init,
)

MORE_PROPOSALS = 2
LAST = 0


def proposal(
    number: int, protocol: int, transforms: list[bytes], spi: bytes = b"", is_last: bool = True
) -> bytes:
    body = b"".join(transforms)
    total = 8 + len(spi) + len(body)
    header = struct.pack(
        "!BBHBBBB",
        LAST if is_last else MORE_PROPOSALS,
        0,
        total,
        number,
        protocol,
        len(spi),
        len(transforms),
    )
    return header + spi + body


def sa_payload_body(proposals: list[bytes]) -> bytes:
    return b"".join(proposals)


def suite(*pairs: tuple[int, int]) -> list[bytes]:
    """Build a transform list with the last one flagged."""
    return [
        build_transform(t_type, t_id, is_last=(index == len(pairs) - 1))
        for index, (t_type, t_id) in enumerate(pairs)
    ]


class TestProposal:
    def test_header_fields_are_parsed(self) -> None:
        parsed = parse_proposal(SafeReader(proposal(7, 1, suite((1, 12), (4, 14)))))
        assert parsed.proposal.number == 7
        assert parsed.proposal.protocol == "IKE"
        assert parsed.is_last is True

    def test_transforms_are_grouped_into_their_proposal(self) -> None:
        parsed = parse_proposal(
            SafeReader(proposal(1, 1, suite((1, 12), (2, 5), (3, 12), (4, 14))))
        )
        assert len(parsed.proposal.transforms) == 4
        assert [t.type for t in parsed.proposal.transforms] == [
            TransformType.ENCR,
            TransformType.PRF,
            TransformType.INTEG,
            TransformType.DH,
        ]

    def test_protocol_names_resolve(self) -> None:
        for protocol_id, name in ((1, "IKE"), (2, "AH"), (3, "ESP")):
            parsed = parse_proposal(SafeReader(proposal(1, protocol_id, suite((1, 12)))))
            assert parsed.proposal.protocol == name

    def test_an_unknown_protocol_is_marked_not_raised(self) -> None:
        parsed = parse_proposal(SafeReader(proposal(1, 99, suite((1, 12)))))
        assert "UNKNOWN" in parsed.proposal.protocol

    def test_an_ike_sa_proposal_carries_no_spi(self) -> None:
        parsed = parse_proposal(SafeReader(proposal(1, 1, suite((1, 12)), spi=b"")))
        assert parsed.spi == ""

    def test_an_esp_child_proposal_carries_a_four_byte_spi(self) -> None:
        """4 bytes for ESP, distinct from the 8-byte IKE SPI in the header."""
        parsed = parse_proposal(SafeReader(proposal(1, 3, suite((1, 20)), spi=b"\xde\xad\xbe\xef")))
        assert parsed.spi == "deadbeef"
        assert len(parsed.spi) == 8

    def test_a_declared_length_below_the_header_is_malformed(self) -> None:
        with pytest.raises(MalformedError):
            parse_proposal(SafeReader(struct.pack("!BBHBBBB", 0, 0, 4, 1, 1, 0, 1)))

    def test_transforms_are_bounded_by_the_proposal(self) -> None:
        """A transform cannot reach into the proposal that follows it."""
        two = proposal(1, 1, suite((1, 12)), is_last=False) + proposal(2, 1, suite((1, 3)))
        reader = SafeReader(two)
        first = parse_proposal(reader)
        assert len(first.proposal.transforms) == 1
        assert first.proposal.transforms[0].id == 12


class TestSAPayload:
    def test_three_proposals_yield_exactly_three(self) -> None:
        body = sa_payload_body(
            [
                proposal(1, 1, suite((1, 20)), is_last=False),
                proposal(2, 1, suite((1, 12)), is_last=False),
                proposal(3, 1, suite((1, 3))),
            ]
        )
        result = parse_sa_payload(SafeReader(body))
        assert len(result.proposals) == 3
        assert result.errors == []

    def test_proposal_numbers_are_preserved(self) -> None:
        body = sa_payload_body(
            [
                proposal(5, 1, suite((1, 20)), is_last=False),
                proposal(9, 1, suite((1, 3))),
            ]
        )
        result = parse_sa_payload(SafeReader(body))
        assert [p.number for p in result.proposals] == [5, 9]

    def test_the_last_flag_terminates_iteration(self) -> None:
        """Trailing bytes after a last-flagged proposal must not be parsed as another."""
        body = proposal(1, 1, suite((1, 20))) + b"\xff" * 24
        result = parse_sa_payload(SafeReader(body))
        assert len(result.proposals) == 1

    def test_the_payload_is_iterable(self) -> None:
        body = proposal(1, 1, suite((1, 20)))
        assert len(list(parse_sa_payload(SafeReader(body)))) == 1

    def test_an_empty_payload_yields_nothing(self) -> None:
        result = parse_sa_payload(SafeReader(b""))
        assert result.proposals == []

    def test_a_malformed_proposal_is_recorded_and_earlier_ones_kept(self) -> None:
        body = proposal(1, 1, suite((1, 20)), is_last=False) + struct.pack(
            "!BBHBBBB", 0, 0, 4, 2, 1, 0, 1
        )
        result = parse_sa_payload(SafeReader(body))
        assert len(result.proposals) == 1
        assert result.errors


class TestAgainstTheSyntheticFixtures:
    """The Step 0.8 builders parse back to exactly what they encode."""

    def _proposals_from(self, message: bytes):  # type: ignore[no-untyped-def]
        from ipsec_sentinel.parser.ike import IKE_HEADER_LENGTH, parse_ike_header, walk_payloads

        header = parse_ike_header(message)
        chain = walk_payloads(
            SafeReader(message[IKE_HEADER_LENGTH : header.length]), header.next_payload
        )
        sa = chain.first_of_type(33)
        assert sa is not None
        return parse_sa_payload(SafeReader(sa.body)).proposals

    def test_the_weak_fixture_parses_to_3des_md5_and_group_2(self) -> None:
        proposals = self._proposals_from(build_weak_ike_sa_init())
        assert len(proposals) == 1
        names = {t.name for t in proposals[0].transforms}
        assert "ENCR_3DES" in names
        assert "AUTH_HMAC_MD5_96" in names
        assert "1024-bit MODP" in names

    def test_the_strong_fixture_parses_to_aes_gcm_256_and_group_20(self) -> None:
        proposals = self._proposals_from(build_strong_ike_sa_init())
        transforms = proposals[0].transforms
        encryption = next(t for t in transforms if t.type is TransformType.ENCR)
        assert encryption.name == "ENCR_AES_GCM_16"
        assert encryption.key_length == 256
        assert any(t.name == "384-bit ECP" for t in transforms)

    def test_every_offered_proposal_is_extracted_not_only_the_first(self) -> None:
        """The fallback proposal is the finding; dropping it loses the point."""
        proposals = self._proposals_from(build_multi_proposal_ike_sa_init())
        assert len(proposals) == 2
        all_names = {t.name for p in proposals for t in p.transforms}
        assert "ENCR_AES_GCM_16" in all_names
        assert "ENCR_3DES" in all_names, "the 3DES fallback was lost"

    def test_proposal_numbers_survive_the_round_trip(self) -> None:
        proposals = self._proposals_from(build_multi_proposal_ike_sa_init())
        assert [p.number for p in proposals] == [1, 2]

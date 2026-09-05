"""Tests for IKEv1 parsing (build plan Step 4.7).

The finding under test is the highest-value one this tool makes: Aggressive Mode plus
a pre-shared key means the authentication hash was sent in cleartext and can be
attacked offline. Both halves are required, and the tests below pin each half
independently so neither can start firing on its own.
"""

from __future__ import annotations

import struct

import pytest

from ipsec_sentinel.parser.ikev1 import (
    DOI_IPSEC,
    parse_ikev1_attributes,
    parse_ikev1_exchange,
    parse_ikev1_sa_payload,
)
from ipsec_sentinel.parser.reader import SafeReader
from tests.fixtures.builders import (
    V1_ATTR_ENCRYPTION,
    V1_ATTR_LIFE_DURATION,
    V1_AUTH_PRE_SHARED_KEY,
    V1_AUTH_RSA_SIGNATURES,
    build_ikev1_aggressive,
    build_ikev1_main_mode,
    build_v1_attribute,
)


class TestExchangeModes:
    def test_main_mode_parses(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_main_mode())
        assert exchange.is_main_mode is True
        assert exchange.is_aggressive is False
        assert exchange.sa is not None
        assert exchange.errors == ()

    def test_aggressive_mode_parses_and_is_flagged(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_aggressive())
        assert exchange.is_aggressive is True
        assert exchange.is_main_mode is False
        assert exchange.errors == ()

    def test_the_header_is_recognised_as_ikev1(self) -> None:
        assert parse_ikev1_exchange(build_ikev1_aggressive()).header.is_ikev1 is True


class TestPSKHashExposure:
    def test_aggressive_plus_psk_exposes_the_hash(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_aggressive(auth_method=V1_AUTH_PRE_SHARED_KEY))
        assert exchange.psk_hash_exposed is True

    def test_aggressive_with_certificates_does_not(self) -> None:
        """Aggressive Mode leaks the identity, but there is no crackable secret."""
        exchange = parse_ikev1_exchange(build_ikev1_aggressive(auth_method=V1_AUTH_RSA_SIGNATURES))
        assert exchange.is_aggressive is True
        assert exchange.psk_hash_exposed is False

    def test_psk_in_main_mode_does_not(self) -> None:
        """Main Mode completes DH before authenticating, so the hash is protected."""
        exchange = parse_ikev1_exchange(build_ikev1_main_mode(auth_method=V1_AUTH_PRE_SHARED_KEY))
        assert exchange.sa is not None
        assert exchange.sa.uses_psk is True
        assert exchange.psk_hash_exposed is False

    def test_main_mode_with_certificates_does_not(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_main_mode(auth_method=V1_AUTH_RSA_SIGNATURES))
        assert exchange.psk_hash_exposed is False


class TestAttributeExtraction:
    @staticmethod
    def _transform(**kwargs: int):  # type: ignore[no-untyped-def]
        exchange = parse_ikev1_exchange(build_ikev1_aggressive(**kwargs))
        assert exchange.sa is not None
        return exchange.sa.transforms[0]

    def test_every_phase_one_attribute_is_extracted(self) -> None:
        transform = self._transform(
            encryption=7,
            hash_alg=4,
            group=14,
            key_length=256,
            life_type=1,
            life_duration=28800,
        )
        assert transform.encryption == "AES_CBC"
        assert transform.hash_algorithm == "SHA2_256"
        assert transform.auth_method == "PRE_SHARED_KEY"
        assert transform.dh_group == 14
        assert transform.dh_group_name == "2048-bit MODP"
        assert transform.key_length == 256
        assert transform.life_type == "seconds"
        assert transform.life_duration == 28800

    def test_the_dh_group_resolves_through_the_shared_registry(self) -> None:
        """The group registry genuinely is shared between v1 and v2; the rest is not."""
        assert self._transform(group=19).dh_group_name == "256-bit ECP"

    def test_an_ikev1_encryption_value_is_not_read_through_the_ikev2_table(self) -> None:
        """IKEv1 value 5 is 3DES-CBC. IKEv2 transform ID 5 is ENCR_DES_IV32."""
        assert self._transform(encryption=5).encryption == "3DES_CBC"

    def test_an_unknown_encryption_value_is_marked_not_dropped(self) -> None:
        assert self._transform(encryption=99).encryption == ("UNKNOWN_Encryption Algorithm_99")

    def test_absent_attributes_are_none_not_invented(self) -> None:
        transform = self._transform()
        assert transform.key_length is None
        assert transform.life_duration is None


class TestAttributeEncodings:
    def test_the_inline_form_is_read(self) -> None:
        attributes = parse_ikev1_attributes(SafeReader(build_v1_attribute(V1_ATTR_ENCRYPTION, 7)))
        assert len(attributes) == 1
        assert attributes[0].is_tv is True
        assert attributes[0].value == 7
        assert attributes[0].class_name == "Encryption Algorithm"

    def test_the_long_form_is_read(self) -> None:
        raw = struct.pack("!HH", V1_ATTR_LIFE_DURATION, 4) + struct.pack("!I", 86400)
        attributes = parse_ikev1_attributes(SafeReader(raw))
        assert attributes[0].is_tv is False
        assert attributes[0].value == 86400
        assert attributes[0].raw == struct.pack("!I", 86400)

    def test_an_over_wide_long_form_is_kept_but_not_interpreted(self) -> None:
        """Widths the RFC does not define are retained raw rather than guessed at."""
        raw = struct.pack("!HH", V1_ATTR_LIFE_DURATION, 8) + b"\x01" * 8
        attribute = parse_ikev1_attributes(SafeReader(raw))[0]
        assert attribute.value is None
        assert attribute.raw == b"\x01" * 8

    def test_both_encodings_can_appear_in_one_transform(self) -> None:
        raw = (
            build_v1_attribute(V1_ATTR_ENCRYPTION, 7)
            + struct.pack("!HH", V1_ATTR_LIFE_DURATION, 4)
            + struct.pack("!I", 3600)
        )
        attributes = parse_ikev1_attributes(SafeReader(raw))
        assert [a.is_tv for a in attributes] == [True, False]


class TestSAPayloadFraming:
    def test_doi_and_situation_are_consumed_before_the_proposals(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_aggressive())
        assert exchange.sa is not None
        assert exchange.sa.doi == DOI_IPSEC
        assert exchange.sa.doi_name == "IPSEC"
        assert exchange.sa.situation == 1
        assert len(exchange.sa.proposals) == 1

    def test_situation_is_only_consumed_for_the_ipsec_doi(self) -> None:
        """Consuming it unconditionally shifts every proposal four bytes left."""
        exchange = parse_ikev1_exchange(build_ikev1_aggressive(doi=0))
        assert exchange.sa is not None
        assert exchange.sa.doi == 0
        assert exchange.sa.doi_name == "ISAKMP"
        assert exchange.sa.proposals, "proposals must still be found without Situation"
        assert exchange.sa.proposals[0].transforms[0].encryption == "3DES_CBC"

    def test_the_proposal_protocol_is_resolved(self) -> None:
        exchange = parse_ikev1_exchange(build_ikev1_aggressive())
        assert exchange.sa is not None
        assert exchange.sa.proposals[0].protocol == "IKE"

    def test_a_truncated_sa_payload_records_an_error_and_does_not_raise(self) -> None:
        sa = parse_ikev1_sa_payload(SafeReader(struct.pack("!II", DOI_IPSEC, 1) + b"\x00\x00\x00"))
        assert sa.errors, "a short proposal must be reported, not swallowed"

    def test_a_proposal_length_below_its_own_header_is_rejected(self) -> None:
        body = struct.pack("!II", DOI_IPSEC, 1) + struct.pack("!BBH", 0, 0, 2)
        sa = parse_ikev1_sa_payload(SafeReader(body))
        assert any("shorter than its own header" in error for error in sa.errors)


class TestRobustness:
    def test_a_truncated_message_does_not_raise(self) -> None:
        data = build_ikev1_aggressive()
        exchange = parse_ikev1_exchange(data[:40])
        assert exchange.header.is_ikev1 is True
        assert exchange.errors, "truncation must be reported"

    def test_a_header_only_message_yields_no_sa(self) -> None:
        data = build_ikev1_aggressive()[:28]
        exchange = parse_ikev1_exchange(data)
        assert exchange.sa is None
        assert exchange.psk_hash_exposed is False

    def test_a_message_shorter_than_the_header_raises(self) -> None:
        from ipsec_sentinel.parser.reader import ParseError

        with pytest.raises(ParseError):
            parse_ikev1_exchange(b"\x00" * 10)

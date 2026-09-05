"""Tests for the fixed IKE header (build plan Step 4.2)."""

from __future__ import annotations

import pytest

from ipsec_sentinel.parser.ike import IKE_HEADER_LENGTH, parse_ike_header
from ipsec_sentinel.parser.reader import MalformedError, TruncatedError
from tests.fixtures.builders import build_ike_header


class TestVersion:
    def test_0x20_is_ikev2(self) -> None:
        assert parse_ike_header(build_ike_header(version=0x20)).version == "IKEv2"

    def test_0x10_is_ikev1(self) -> None:
        assert parse_ike_header(build_ike_header(version=0x10)).version == "IKEv1"

    def test_version_nibbles_are_split(self) -> None:
        """Two nibbles in one byte; reading the whole byte would misreport minor."""
        header = parse_ike_header(build_ike_header(version=0x21))
        assert header.version_major == 2
        assert header.version_minor == 1

    def test_unknown_version_is_flagged_not_raised(self) -> None:
        """A parser must not abort on a version nobody has shipped yet."""
        header = parse_ike_header(build_ike_header(version=0x30))
        assert header.unknown_version is True
        assert "0x30" in header.version

    def test_known_version_is_not_flagged(self) -> None:
        assert parse_ike_header(build_ike_header(version=0x20)).unknown_version is False


class TestExchangeType:
    def test_ikev2_type_34_is_sa_init(self) -> None:
        header = parse_ike_header(build_ike_header(version=0x20, exchange_type=34))
        assert header.exchange_type_name == "IKE_SA_INIT"

    def test_ikev2_type_35_is_ike_auth(self) -> None:
        header = parse_ike_header(build_ike_header(version=0x20, exchange_type=35))
        assert header.exchange_type_name == "IKE_AUTH"

    def test_ikev1_type_4_is_aggressive_mode(self) -> None:
        """The highest-value finding the tool can produce."""
        header = parse_ike_header(build_ike_header(version=0x10, exchange_type=4))
        assert header.exchange_type_name == "Aggressive Mode"
        assert header.is_aggressive is True

    def test_ikev1_type_2_is_main_mode_and_not_aggressive(self) -> None:
        header = parse_ike_header(build_ike_header(version=0x10, exchange_type=2))
        assert "Main Mode" in header.exchange_type_name
        assert header.is_aggressive is False

    def test_exchange_type_4_under_ikev2_is_not_aggressive(self) -> None:
        """Type 4 means Aggressive Mode only in IKEv1; IKEv2 reuses the number space."""
        header = parse_ike_header(build_ike_header(version=0x20, exchange_type=4))
        assert header.is_aggressive is False

    def test_unknown_exchange_type_is_marked_not_raised(self) -> None:
        header = parse_ike_header(build_ike_header(version=0x20, exchange_type=99))
        assert "UNKNOWN" in header.exchange_type_name
        assert header.exchange_type == 99


class TestFlags:
    def test_initiator_bit(self) -> None:
        assert parse_ike_header(build_ike_header(flags=0x08)).is_initiator is True
        assert parse_ike_header(build_ike_header(flags=0x00)).is_initiator is False

    def test_response_bit(self) -> None:
        assert parse_ike_header(build_ike_header(flags=0x20)).is_response is True
        assert parse_ike_header(build_ike_header(flags=0x00)).is_response is False

    def test_version_bit(self) -> None:
        assert parse_ike_header(build_ike_header(flags=0x10)).higher_version_supported is True

    def test_flags_combine(self) -> None:
        header = parse_ike_header(build_ike_header(flags=0x28))
        assert header.is_initiator is True
        assert header.is_response is True
        assert header.higher_version_supported is False

    def test_raw_flags_are_retained(self) -> None:
        assert parse_ike_header(build_ike_header(flags=0x2A)).flags == 0x2A


class TestSPIs:
    def test_spis_are_lowercase_hex(self) -> None:
        header = parse_ike_header(
            build_ike_header(i_spi=bytes.fromhex("AABBCCDDEEFF0011"), r_spi=b"\x00" * 8)
        )
        assert header.initiator_spi == "aabbccddeeff0011"
        assert header.responder_spi == "0000000000000000"

    def test_ike_spis_are_eight_bytes(self) -> None:
        """Sixteen hex characters. The ESP SPI is four bytes and a different field."""
        header = parse_ike_header(build_ike_header())
        assert len(header.initiator_spi) == 16
        assert len(header.responder_spi) == 16


class TestLengthValidation:
    def test_a_27_byte_header_is_truncated(self) -> None:
        with pytest.raises(TruncatedError):
            parse_ike_header(build_ike_header()[:27])

    def test_empty_input_is_truncated(self) -> None:
        with pytest.raises(TruncatedError):
            parse_ike_header(b"")

    def test_a_length_field_below_the_header_size_is_malformed(self) -> None:
        """A message cannot be shorter than its own fixed header."""
        with pytest.raises(MalformedError, match="27"):
            parse_ike_header(build_ike_header(length=27))

    def test_a_zero_length_field_is_malformed(self) -> None:
        with pytest.raises(MalformedError):
            parse_ike_header(build_ike_header(length=0))

    def test_a_length_field_longer_than_the_data_is_truncated(self) -> None:
        with pytest.raises(TruncatedError, match="declares"):
            parse_ike_header(build_ike_header(length=9999))

    def test_a_length_exactly_matching_the_data_is_accepted(self) -> None:
        assert parse_ike_header(build_ike_header(length=28)).length == 28

    def test_trailing_data_beyond_the_declared_length_is_allowed(self) -> None:
        """UDP may deliver padding; the declared length governs."""
        header = parse_ike_header(build_ike_header(length=28) + b"\xff" * 40)
        assert header.length == 28


class TestMessageId:
    def test_message_id_is_big_endian(self) -> None:
        assert parse_ike_header(build_ike_header(message_id=0x01020304)).message_id == 0x01020304

    def test_header_length_constant(self) -> None:
        assert IKE_HEADER_LENGTH == 28
        assert len(build_ike_header()) == 28

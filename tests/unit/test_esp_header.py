"""Tests for the ESP header parser (build plan Step 5.1)."""

from __future__ import annotations

import struct

import pytest

from ipsec_sentinel.models import ESPFlow, IKEExchange
from ipsec_sentinel.parser.esp import ESP_HEADER_LENGTH, parse_esp_header
from ipsec_sentinel.parser.reader import TruncatedError


def esp_bytes(spi: int, sequence: int, payload: bytes = b"") -> bytes:
    return struct.pack("!II", spi, sequence) + payload


class TestSPI:
    def test_the_spi_is_lowercase_hex(self) -> None:
        assert parse_esp_header(esp_bytes(0xDEADBEEF, 1)).spi == "deadbeef"

    def test_a_small_spi_keeps_its_leading_zeros(self) -> None:
        """Trimming them would make two distinct SAs collide in a flow key."""
        assert parse_esp_header(esp_bytes(0x00000001, 1)).spi == "00000001"

    def test_the_spi_is_exactly_eight_hex_characters(self) -> None:
        for value in (0x1, 0xFFFFFFFF, 0x0A0B0C0D):
            assert len(parse_esp_header(esp_bytes(value, 1)).spi) == 8


class TestSequenceNumber:
    def test_the_sequence_number_is_big_endian(self) -> None:
        """Little-endian would read sequence 1 as 16,777,216."""
        assert parse_esp_header(esp_bytes(1, 1)).sequence == 1
        assert parse_esp_header(esp_bytes(1, 0x01020304)).sequence == 0x01020304

    def test_the_maximum_sequence_number_is_read(self) -> None:
        assert parse_esp_header(esp_bytes(1, 0xFFFFFFFF)).sequence == 0xFFFFFFFF

    def test_sequence_zero_is_legal_and_read(self) -> None:
        """Zero appears after a 32-bit wrap; treating it as absent would lose a packet."""
        assert parse_esp_header(esp_bytes(1, 0)).sequence == 0


class TestPayload:
    def test_the_rest_is_opaque_and_its_length_recorded(self) -> None:
        header = parse_esp_header(esp_bytes(1, 1, b"\xa5" * 96))
        assert header.payload_length == 96

    def test_a_header_with_no_payload_is_legal(self) -> None:
        assert parse_esp_header(esp_bytes(1, 1)).payload_length == 0

    def test_the_ciphertext_is_not_retained(self) -> None:
        """Storing ciphertext would give this tool a reason to be trusted less.

        Nothing downstream can decrypt it, so keeping it buys nothing and turns every
        report into a container for someone's encrypted traffic.
        """
        header = parse_esp_header(esp_bytes(1, 1, b"\xa5" * 96))
        assert not any(isinstance(value, bytes | bytearray) for value in vars(header).values())


class TestTruncation:
    def test_seven_bytes_raises(self) -> None:
        with pytest.raises(TruncatedError):
            parse_esp_header(b"\x00" * 7)

    def test_exactly_eight_bytes_is_enough(self) -> None:
        assert parse_esp_header(b"\x00" * ESP_HEADER_LENGTH).sequence == 0

    def test_empty_input_raises(self) -> None:
        with pytest.raises(TruncatedError):
            parse_esp_header(b"")


class TestSPIWidthIsNotConfusedWithIKE:
    """The ESP SPI is 4 bytes; the IKE SPI is 8. They are different identifiers.

    Conflating them is not a cosmetic error: an ESP SPI widened to 8 bytes would never
    match its own flow key, and an IKE SPI truncated to 4 would silently merge two
    distinct negotiations between the same pair of hosts.
    """

    def test_the_esp_spi_is_half_the_width_of_an_ike_spi(self) -> None:
        esp = parse_esp_header(esp_bytes(0xDEADBEEF, 1))
        assert len(esp.spi) == 8  # 4 bytes
        assert len(_ike_exchange().initiator_spi) == 16  # 8 bytes

    def test_the_models_keep_them_in_separate_fields(self) -> None:
        assert "spi" in ESPFlow.model_fields
        assert "initiator_spi" in IKEExchange.model_fields
        assert "spi" not in IKEExchange.model_fields

    def test_an_ike_spi_is_never_accepted_as_an_esp_spi_by_width(self) -> None:
        """A 4-byte read of an 8-byte IKE SPI keeps only its first half."""
        ike_spi = bytes.fromhex("1122334455667788")
        assert parse_esp_header(ike_spi + b"\x00" * 4).spi == "11223344"


def _ike_exchange() -> IKEExchange:
    from datetime import UTC, datetime

    return IKEExchange(
        initiator_spi="11" * 8,
        responder_spi="22" * 8,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        timestamp=datetime.now(UTC),
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )

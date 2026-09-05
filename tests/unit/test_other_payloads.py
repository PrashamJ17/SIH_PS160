"""Tests for KE, nonce, notify and vendor ID payloads (build plan Step 4.6)."""

from __future__ import annotations

import struct
import warnings

import pytest

from ipsec_sentinel.parser.constants import KELengthWarning
from ipsec_sentinel.parser.ike import (
    parse_ke_payload,
    parse_nonce_payload,
    parse_notify_payload,
    parse_vendor_id_payload,
)
from ipsec_sentinel.parser.reader import SafeReader, TruncatedError


def ke_body(group: int, key_bytes: int) -> bytes:
    return struct.pack("!HH", group, 0) + b"\xab" * key_bytes


def notify_body(protocol: int, spi: bytes, notify_type: int, data: bytes = b"") -> bytes:
    return struct.pack("!BBH", protocol, len(spi), notify_type) + spi + data


class TestKEPayload:
    def test_group_and_public_value_are_read(self) -> None:
        parsed = parse_ke_payload(SafeReader(ke_body(20, 96)))
        assert parsed.dh_group == 20
        assert parsed.public_value_length == 96

    def test_a_matching_group_produces_no_warning(self) -> None:
        """256-bit ECP is 64 bytes and nothing else is; the length corroborates it."""
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            parsed = parse_ke_payload(SafeReader(ke_body(19, 64)), declared_group=19)
        assert parsed.length_check is not None
        assert parsed.length_check.consistent is True
        assert parsed.length_check.ambiguous is False

    def test_a_mismatching_group_warns_and_keeps_both_values(self) -> None:
        """The declared group wins; the disagreement is intelligence, not an error."""
        with pytest.warns(KELengthWarning):
            parsed = parse_ke_payload(SafeReader(ke_body(14, 128)), declared_group=14)
        assert parsed.dh_group == 14
        assert parsed.public_value_length == 128
        assert parsed.length_check is not None
        assert parsed.length_check.consistent is False

    def test_the_ambiguous_96_byte_length_is_reported_as_ambiguous(self) -> None:
        """768-bit MODP and 384-bit ECP are both 96 bytes."""
        with pytest.warns(KELengthWarning, match="ambiguous"):
            parsed = parse_ke_payload(SafeReader(ke_body(1, 96)), declared_group=1)
        assert parsed.length_check is not None
        assert parsed.length_check.ambiguous is True

    def test_without_a_declared_group_no_cross_check_is_attempted(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            parsed = parse_ke_payload(SafeReader(ke_body(14, 256)))
        assert parsed.length_check is None

    def test_the_public_value_is_retained(self) -> None:
        parsed = parse_ke_payload(SafeReader(ke_body(19, 64)))
        assert len(parsed.public_value) == 64

    def test_a_truncated_ke_payload_raises(self) -> None:
        with pytest.raises(TruncatedError):
            parse_ke_payload(SafeReader(b"\x00"))


class TestNoncePayload:
    def test_length_is_reported(self) -> None:
        assert parse_nonce_payload(SafeReader(b"\xaa" * 32)).length == 32

    def test_an_empty_nonce_is_length_zero(self) -> None:
        assert parse_nonce_payload(SafeReader(b"")).length == 0

    def test_a_short_nonce_is_flagged(self) -> None:
        """RFC 7296 requires at least 16 bytes; less is worth recording."""
        assert parse_nonce_payload(SafeReader(b"\xaa" * 8)).below_minimum is True
        assert parse_nonce_payload(SafeReader(b"\xaa" * 32)).below_minimum is False


class TestNotifyPayload:
    def test_nat_detection_source_ip_resolves_by_name(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(0, b"", 16390)))
        assert parsed.notify_type == 16390
        assert parsed.notify_name == "NAT_DETECTION_SOURCE_IP"

    def test_no_proposal_chosen_resolves(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(1, b"", 14)))
        assert parsed.notify_name == "NO_PROPOSAL_CHOSEN"

    def test_invalid_ke_payload_yields_the_responders_preferred_group(self) -> None:
        """Free intelligence: the responder says which group it actually wanted."""
        parsed = parse_notify_payload(SafeReader(notify_body(1, b"", 17, struct.pack("!H", 20))))
        assert parsed.notify_name == "INVALID_KE_PAYLOAD"
        assert parsed.preferred_dh_group == 20

    def test_invalid_ke_payload_without_data_yields_no_group(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(1, b"", 17)))
        assert parsed.preferred_dh_group is None

    def test_a_preferred_group_is_only_read_for_invalid_ke(self) -> None:
        """Other notifies carry unrelated data; reading it as a group would invent one."""
        parsed = parse_notify_payload(SafeReader(notify_body(1, b"", 16390, struct.pack("!H", 20))))
        assert parsed.preferred_dh_group is None

    def test_an_unknown_notify_type_is_marked_not_raised(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(0, b"", 40000)))
        assert parsed.notify_name == "UNKNOWN_NOTIFY_40000"

    def test_an_spi_is_read_when_present(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(3, b"\xde\xad\xbe\xef", 14)))
        assert parsed.spi == "deadbeef"
        assert parsed.protocol == "ESP"

    def test_notification_data_is_retained(self) -> None:
        parsed = parse_notify_payload(SafeReader(notify_body(0, b"", 16390, b"\x01\x02\x03")))
        assert parsed.data == b"\x01\x02\x03"

    def test_a_truncated_notify_raises(self) -> None:
        with pytest.raises(TruncatedError):
            parse_notify_payload(SafeReader(b"\x01\x00"))


class TestVendorIDPayload:
    def test_hex_is_lowercase_and_stable(self) -> None:
        parsed = parse_vendor_id_payload(
            SafeReader(bytes.fromhex("AFCAD71368A1F1C96B8696FC77570100"))
        )
        assert parsed.vendor_id == "afcad71368a1f1c96b8696fc77570100"
        assert parsed.vendor_id == parsed.vendor_id.lower()

    def test_raw_bytes_are_retained(self) -> None:
        parsed = parse_vendor_id_payload(SafeReader(b"\x01\x02\x03"))
        assert parsed.raw == b"\x01\x02\x03"

    def test_an_empty_vendor_id_is_allowed(self) -> None:
        assert parse_vendor_id_payload(SafeReader(b"")).vendor_id == ""

    def test_a_printable_vendor_id_is_decoded_as_a_hint(self) -> None:
        """Some implementations put their name in cleartext; it is worth surfacing."""
        parsed = parse_vendor_id_payload(SafeReader(b"strongSwan 5.9.8"))
        assert parsed.printable == "strongSwan 5.9.8"

    def test_a_binary_vendor_id_has_no_printable_form(self) -> None:
        assert parse_vendor_id_payload(SafeReader(b"\x00\x01\x02\xff")).printable is None

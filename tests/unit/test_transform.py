"""Tests for transform parsing down to the attribute level (build plan Step 4.4).

Key length is an *attribute* of the encryption transform, not part of its ID: AES-128
and AES-256 are both transform 12. A parser that stops at the transform level cannot
tell them apart, and the problem statement asks for both.
"""

from __future__ import annotations

import struct

import pytest

from ipsec_sentinel.models import TransformType
from ipsec_sentinel.parser.constants import ATTRIBUTE_KEY_LENGTH, dh_group_bits
from ipsec_sentinel.parser.ike import parse_transform
from ipsec_sentinel.parser.reader import SafeReader, TruncatedError
from tests.fixtures.builders import build_transform


def tv_attribute(attr_type: int, value: int) -> bytes:
    """Type/value form: the AF bit set, value inline."""
    return struct.pack("!HH", 0x8000 | attr_type, value)


def tlv_attribute(attr_type: int, value: bytes) -> bytes:
    """Type/length/value form: the AF bit clear, explicit length."""
    return struct.pack("!HH", attr_type & 0x7FFF, len(value)) + value


def transform(t_type: int, t_id: int, attributes: bytes = b"", is_last: bool = True) -> bytes:
    total = 8 + len(attributes)
    return struct.pack("!BBHBBH", 0 if is_last else 3, 0, total, t_type, 0, t_id) + attributes


class TestEncryption:
    def test_aes_cbc_with_a_key_length_attribute(self) -> None:
        parsed = parse_transform(SafeReader(build_transform(1, 12, key_length=256, is_last=True)))
        assert parsed.transform.type is TransformType.ENCR
        assert parsed.transform.id == 12
        assert parsed.transform.name == "ENCR_AES_CBC"
        assert parsed.transform.key_length == 256

    def test_aes_cbc_without_an_attribute_has_no_key_length(self) -> None:
        parsed = parse_transform(SafeReader(build_transform(1, 12, is_last=True)))
        assert parsed.transform.name == "ENCR_AES_CBC"
        assert parsed.transform.key_length is None

    def test_aes_gcm_16_with_a_key_length(self) -> None:
        parsed = parse_transform(SafeReader(build_transform(1, 20, key_length=256, is_last=True)))
        assert parsed.transform.name == "ENCR_AES_GCM_16"
        assert parsed.transform.key_length == 256

    def test_aes_128_and_aes_256_are_distinguishable(self) -> None:
        """The reason this parser goes to the attribute level at all."""
        a = parse_transform(SafeReader(build_transform(1, 12, key_length=128, is_last=True)))
        b = parse_transform(SafeReader(build_transform(1, 12, key_length=256, is_last=True)))
        assert a.transform.id == b.transform.id
        assert a.transform != b.transform

    def test_3des_resolves(self) -> None:
        parsed = parse_transform(SafeReader(build_transform(1, 3, is_last=True)))
        assert parsed.transform.name == "ENCR_3DES"


class TestOtherTransformTypes:
    def test_integrity_none(self) -> None:
        parsed = parse_transform(SafeReader(transform(3, 0)))
        assert parsed.transform.type is TransformType.INTEG
        assert parsed.transform.name == "NONE"

    def test_integrity_md5(self) -> None:
        assert parse_transform(SafeReader(transform(3, 1))).transform.name == "AUTH_HMAC_MD5_96"

    def test_prf_resolves(self) -> None:
        assert parse_transform(SafeReader(transform(2, 5))).transform.name == "PRF_HMAC_SHA2_256"

    def test_dh_group_two_reports_1024_bits(self) -> None:
        parsed = parse_transform(SafeReader(transform(4, 2)))
        assert parsed.transform.type is TransformType.DH
        assert parsed.transform.name == "1024-bit MODP"
        assert dh_group_bits(parsed.transform.id) == 1024

    def test_esn_resolves(self) -> None:
        assert parse_transform(SafeReader(transform(5, 1))).transform.type is TransformType.ESN


class TestUnknownValues:
    def test_unknown_transform_id_is_marked_not_raised(self) -> None:
        parsed = parse_transform(SafeReader(transform(1, 99)))
        assert parsed.transform.name == "UNKNOWN_ENCR_99"

    def test_unknown_transform_type_is_marked_not_raised(self) -> None:
        parsed = parse_transform(SafeReader(transform(200, 7)))
        assert "UNKNOWN" in parsed.transform.name
        assert parsed.transform.type is None


class TestAttributeFormats:
    def test_tv_attribute_is_parsed(self) -> None:
        parsed = parse_transform(
            SafeReader(transform(1, 12, tv_attribute(ATTRIBUTE_KEY_LENGTH, 192)))
        )
        assert parsed.transform.key_length == 192
        assert parsed.attributes[0].is_tv is True

    def test_tlv_attribute_is_parsed(self) -> None:
        """Key length may legally arrive in the long form too."""
        parsed = parse_transform(
            SafeReader(transform(1, 12, tlv_attribute(ATTRIBUTE_KEY_LENGTH, b"\x01\x00")))
        )
        assert parsed.attributes[0].is_tv is False
        assert parsed.transform.key_length == 256

    def test_multiple_attributes_are_all_retained(self) -> None:
        attributes = tv_attribute(ATTRIBUTE_KEY_LENGTH, 128) + tv_attribute(9, 42)
        parsed = parse_transform(SafeReader(transform(1, 12, attributes)))
        assert len(parsed.attributes) == 2
        assert parsed.transform.key_length == 128

    def test_a_non_key_length_attribute_does_not_set_key_length(self) -> None:
        parsed = parse_transform(SafeReader(transform(1, 12, tv_attribute(9, 42))))
        assert parsed.transform.key_length is None

    def test_a_tlv_key_length_of_odd_width_is_ignored_not_guessed(self) -> None:
        """Rather than invent a value from a width the RFC does not define."""
        parsed = parse_transform(
            SafeReader(transform(1, 12, tlv_attribute(ATTRIBUTE_KEY_LENGTH, b"\x01\x02\x03")))
        )
        assert parsed.transform.key_length is None


class TestStructure:
    def test_last_flag_is_reported(self) -> None:
        assert parse_transform(SafeReader(transform(1, 12, is_last=True))).is_last is True
        assert parse_transform(SafeReader(transform(1, 12, is_last=False))).is_last is False

    def test_the_reader_advances_exactly_one_transform(self) -> None:
        chain = transform(1, 12, is_last=False) + transform(4, 14, is_last=True)
        reader = SafeReader(chain)
        first = parse_transform(reader)
        assert first.transform.id == 12
        second = parse_transform(reader)
        assert second.transform.id == 14
        assert reader.at_end()


class TestTruncation:
    def test_a_truncated_header_raises(self) -> None:
        with pytest.raises(TruncatedError):
            parse_transform(SafeReader(transform(1, 12)[:5]))

    def test_a_truncated_attribute_raises(self) -> None:
        body = transform(1, 12, tv_attribute(ATTRIBUTE_KEY_LENGTH, 256))
        with pytest.raises(TruncatedError):
            parse_transform(SafeReader(body[:-2]))

    def test_a_tlv_attribute_claiming_more_than_remains_raises(self) -> None:
        attributes = struct.pack("!HH", ATTRIBUTE_KEY_LENGTH, 400) + b"\xaa" * 4
        with pytest.raises(TruncatedError):
            parse_transform(SafeReader(transform(1, 12, attributes)))

    def test_a_declared_length_below_the_header_raises(self) -> None:
        from ipsec_sentinel.parser.reader import MalformedError

        bad = struct.pack("!BBHBBH", 0, 0, 4, 1, 0, 12)
        with pytest.raises(MalformedError):
            parse_transform(SafeReader(bad))

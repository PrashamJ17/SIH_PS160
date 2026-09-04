"""Tests for the synthetic IKE packet builders (build plan Step 0.8).

Every length field is checked against the bytes actually emitted. A builder that
mis-states a length would hand the Phase 4 parser a corrupt fixture and make a real
parser bug look like a passing test — the worst possible failure mode here.
"""

from __future__ import annotations

import struct

import pytest

from ipsec_sentinel.models import Proposal, Transform, TransformType
from ipsec_sentinel.parser.constants import ATTRIBUTE_KEY_LENGTH
from tests.fixtures.builders import (
    EXCHANGE_IKE_SA_INIT,
    EXCHANGE_V1_AGGRESSIVE,
    IKE_HEADER_LENGTH,
    LAST_SUBSTRUCTURE,
    MORE_PROPOSALS,
    MORE_TRANSFORMS,
    PAYLOAD_SA,
    PROTOCOL_IKE,
    TRANSFORM_HEADER_LENGTH,
    VERSION_IKEV1,
    VERSION_IKEV2,
    build_ike_header,
    build_ike_sa_init,
    build_ikev1_aggressive,
    build_ke_payload,
    build_multi_proposal_ike_sa_init,
    build_proposal,
    build_sa_payload,
    build_strong_ike_sa_init,
    build_transform,
    build_weak_ike_sa_init,
)


def header_length_field(message: bytes) -> int:
    return int(struct.unpack("!I", message[24:28])[0])


class TestHeader:
    def test_header_is_exactly_28_bytes(self) -> None:
        assert len(build_ike_header()) == IKE_HEADER_LENGTH

    def test_header_is_28_bytes_for_every_parameter_combination(self) -> None:
        assert len(build_ike_header(version=VERSION_IKEV1, exchange_type=4, flags=0)) == 28

    def test_spis_land_at_the_right_offsets(self) -> None:
        h = build_ike_header(i_spi=b"\x01" * 8, r_spi=b"\x02" * 8)
        assert h[0:8] == b"\x01" * 8
        assert h[8:16] == b"\x02" * 8

    def test_fixed_fields_decode(self) -> None:
        h = build_ike_header(next_payload=33, version=0x20, exchange_type=34, flags=0x08)
        nxt, ver, exch, flags = struct.unpack("!BBBB", h[16:20])
        assert (nxt, ver, exch, flags) == (33, 0x20, 34, 0x08)

    def test_message_id_and_length_are_big_endian(self) -> None:
        h = build_ike_header(message_id=0x01020304, length=0x0A0B0C0D)
        assert h[20:24] == b"\x01\x02\x03\x04"
        assert h[24:28] == b"\x0a\x0b\x0c\x0d"

    def test_length_defaults_to_the_header_length(self) -> None:
        assert header_length_field(build_ike_header()) == IKE_HEADER_LENGTH

    def test_length_can_be_forced_wrong_for_negative_tests(self) -> None:
        """Phase 4 needs to build deliberately malformed input."""
        assert header_length_field(build_ike_header(length=9999)) == 9999


class TestTransform:
    def test_length_without_a_key_length_attribute(self) -> None:
        t = build_transform(t_type=1, t_id=3)
        assert len(t) == TRANSFORM_HEADER_LENGTH
        assert struct.unpack("!H", t[2:4])[0] == len(t)

    def test_length_with_a_key_length_attribute(self) -> None:
        t = build_transform(t_type=1, t_id=12, key_length=256)
        assert len(t) == TRANSFORM_HEADER_LENGTH + 4
        assert struct.unpack("!H", t[2:4])[0] == len(t)

    def test_key_length_attribute_uses_tv_form_and_type_14(self) -> None:
        t = build_transform(t_type=1, t_id=12, key_length=256)
        attr_header, value = struct.unpack("!HH", t[8:12])
        assert attr_header & 0x8000, "AF bit must be set for TV form"
        assert attr_header & 0x7FFF == ATTRIBUTE_KEY_LENGTH
        assert value == 256

    @pytest.mark.parametrize("key_length", [128, 192, 256])
    def test_key_length_value_round_trips(self, key_length: int) -> None:
        t = build_transform(t_type=1, t_id=12, key_length=key_length)
        assert struct.unpack("!H", t[10:12])[0] == key_length

    def test_type_and_id_decode(self) -> None:
        t = build_transform(t_type=4, t_id=20)
        t_type, _, t_id = struct.unpack("!BBH", t[4:8])
        assert (t_type, t_id) == (4, 20)

    def test_last_flag(self) -> None:
        assert build_transform(1, 3, is_last=True)[0] == LAST_SUBSTRUCTURE
        assert build_transform(1, 3, is_last=False)[0] == MORE_TRANSFORMS


class TestProposal:
    def test_length_field_matches_actual_length(self) -> None:
        transforms = [build_transform(1, 12, 256), build_transform(4, 20, is_last=True)]
        p = build_proposal(1, PROTOCOL_IKE, transforms, is_last=True)
        assert struct.unpack("!H", p[2:4])[0] == len(p)

    def test_header_fields_decode(self) -> None:
        transforms = [build_transform(1, 3, is_last=True)]
        p = build_proposal(number=7, protocol=PROTOCOL_IKE, transforms=transforms, is_last=True)
        num, proto, spi_size, n_transforms = struct.unpack("!BBBB", p[4:8])
        assert (num, proto, spi_size, n_transforms) == (7, PROTOCOL_IKE, 0, 1)

    def test_spi_is_included_and_counted(self) -> None:
        p = build_proposal(1, 3, [build_transform(1, 12, is_last=True)], spi=b"\xde\xad\xbe\xef")
        assert p[6] == 4
        assert struct.unpack("!H", p[2:4])[0] == len(p)

    def test_last_flag(self) -> None:
        t = [build_transform(1, 3, is_last=True)]
        assert build_proposal(1, 1, t, is_last=True)[0] == LAST_SUBSTRUCTURE
        assert build_proposal(1, 1, t, is_last=False)[0] == MORE_PROPOSALS


class TestSAPayload:
    def test_length_field_matches_actual_length(self) -> None:
        p = build_proposal(1, PROTOCOL_IKE, [build_transform(1, 3, is_last=True)], is_last=True)
        sa = build_sa_payload([p])
        assert struct.unpack("!H", sa[2:4])[0] == len(sa)

    def test_ke_payload_length_matches_and_declares_its_group(self) -> None:
        ke = build_ke_payload(20)
        assert struct.unpack("!H", ke[2:4])[0] == len(ke)
        assert struct.unpack("!H", ke[4:6])[0] == 20

    def test_ke_public_value_length_corroborates_the_group(self) -> None:
        """96 bytes for 384-bit ECP, 128 for 1024-bit MODP."""
        assert len(build_ke_payload(20)) - 8 == 96
        assert len(build_ke_payload(2)) - 8 == 128


class TestFullMessages:
    @pytest.mark.parametrize(
        "message",
        [build_weak_ike_sa_init(), build_strong_ike_sa_init(), build_multi_proposal_ike_sa_init()],
    )
    def test_header_length_field_matches_the_real_total(self, message: bytes) -> None:
        assert header_length_field(message) == len(message)

    def test_weak_and_strong_differ(self) -> None:
        assert build_weak_ike_sa_init() != build_strong_ike_sa_init()

    def test_messages_are_ikev2_sa_init(self) -> None:
        for message in (build_weak_ike_sa_init(), build_strong_ike_sa_init()):
            assert message[17] == VERSION_IKEV2
            assert message[18] == EXCHANGE_IKE_SA_INIT
            assert message[16] == PAYLOAD_SA

    def test_builders_are_deterministic(self) -> None:
        assert build_weak_ike_sa_init() == build_weak_ike_sa_init()

    def test_weak_message_carries_3des_and_group_2(self) -> None:
        m = build_weak_ike_sa_init()
        assert build_transform(1, 3) in m, "3DES transform must appear"
        assert build_transform(4, 2, is_last=True) in m, "DH group 2 transform must appear"

    def test_strong_message_carries_aes_gcm_256_and_group_20(self) -> None:
        m = build_strong_ike_sa_init()
        assert build_transform(1, 20, key_length=256) in m
        assert build_transform(4, 20, is_last=True) in m

    def test_multi_proposal_message_contains_both_proposals(self) -> None:
        """The 3DES fallback must be present even though a strong option is offered."""
        m = build_multi_proposal_ike_sa_init()
        assert build_transform(1, 20, key_length=256) in m
        assert build_transform(1, 3) in m

    def test_arbitrary_proposal_list_builds_a_consistent_message(self) -> None:
        p = Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128),
                Transform(type=TransformType.INTEG, id=2, name="AUTH_HMAC_SHA1_96"),
                Transform(type=TransformType.DH, id=14, name="2048-bit MODP"),
            ],
        )
        m = build_ike_sa_init([p])
        assert header_length_field(m) == len(m)


class TestIKEv1Aggressive:
    def test_header_length_field_matches_the_real_total(self) -> None:
        m = build_ikev1_aggressive()
        assert header_length_field(m) == len(m)

    def test_version_is_ikev1_and_exchange_is_aggressive(self) -> None:
        m = build_ikev1_aggressive()
        assert m[17] == VERSION_IKEV1
        assert m[18] == EXCHANGE_V1_AGGRESSIVE

    def test_sa_payload_length_matches(self) -> None:
        m = build_ikev1_aggressive()
        sa = m[IKE_HEADER_LENGTH:]
        assert struct.unpack("!H", sa[2:4])[0] <= len(sa)

    def test_carries_a_psk_auth_method_attribute(self) -> None:
        """Aggressive Mode plus PSK is the critical finding; the attribute must be present."""
        assert struct.pack("!HH", 0x8000 | 3, 1) in build_ikev1_aggressive()

    def test_non_psk_auth_method_is_buildable_for_the_negative_case(self) -> None:
        m = build_ikev1_aggressive(auth_method=3)
        assert struct.pack("!HH", 0x8000 | 3, 3) in m
        assert struct.pack("!HH", 0x8000 | 3, 1) not in m

    def test_differs_from_the_ikev2_messages(self) -> None:
        assert build_ikev1_aggressive() != build_weak_ike_sa_init()

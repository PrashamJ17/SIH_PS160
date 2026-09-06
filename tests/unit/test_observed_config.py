"""Tests for reconstructing a configuration from a negotiation.

The strong test is :class:`TestAgainstTheCorpusManifests`. Every sweep capture was
produced from a configuration recorded in its own manifest, so the corpus is an oracle:
what this module recovers from the wire must equal what the testbed set out to negotiate.
That is a comparison against ground truth rather than against this project's own idea of
the format.

The rest guard the refusals. A configuration built from a proposal that was only half
understood gets hardened, rendered, and handed to an operator to apply — and the guessed
parts are then indistinguishable from the read ones.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ipsec_sentinel.models import IKEExchange, Proposal, Transform, TransformType
from ipsec_sentinel.remediate.observed import (
    ASSUMED_CHILD_LIFETIME_S,
    ASSUMED_IKE_LIFETIME_S,
    DH_BY_ID,
    config_from_exchange,
    config_from_proposal,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"


def manifests(limit: int = 40) -> list[Path]:
    return sorted(SWEEP.glob("*/manifest.json"))[:limit] if SWEEP.is_dir() else []


MANIFESTS = manifests()
needs_corpus = pytest.mark.skipif(not MANIFESTS, reason="the sweep corpus is not present")


def transform(kind: TransformType, identifier: int, name: str, key_length: int | None = None):  # type: ignore[no-untyped-def]
    return Transform(type=kind, id=identifier, name=name, key_length=key_length)


def proposal(transforms: list[Transform]) -> Proposal:
    return Proposal(number=1, protocol="IKE", transforms=transforms)


AES256_SHA256_MODP2048 = proposal(
    [
        transform(TransformType.ENCR, 12, "ENCR_AES_CBC", 256),
        transform(TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
        transform(TransformType.PRF, 5, "PRF_HMAC_SHA2_256"),
        transform(TransformType.DH, 14, "2048-bit MODP"),
    ]
)


@needs_corpus
class TestAgainstTheCorpusManifests:
    """The oracle: every capture records the configuration it was produced from."""

    @pytest.mark.parametrize("manifest_path", MANIFESTS, ids=lambda p: p.parent.name[:28])
    def test_the_recovered_configuration_matches_the_intent(self, manifest_path: Path) -> None:
        from ipsec_sentinel.analyse import read_tunnels

        manifest = json.loads(manifest_path.read_text())
        intent = manifest["intent"]
        tunnels = [t for t in read_tunnels(manifest_path.parent / "capture_outer.pcap") if t.ike]
        if not tunnels:
            pytest.skip("this capture holds no readable negotiation")

        recovered = config_from_exchange(tunnels[0].ike)  # type: ignore[arg-type]
        assert recovered.ok, recovered.reason
        config = recovered.config
        assert config is not None
        assert config.encryption == intent["encryption"]
        assert config.integrity == intent["integrity"]
        assert config.prf == intent["prf"]
        assert config.dh_group == intent["dh_group"]
        assert config.ike_version == intent["ike_version"]

    def test_an_aead_configuration_recovers_without_an_integrity_algorithm(self) -> None:
        """AES-GCM authenticates; inventing an integrity transform would be a wrong config."""
        from ipsec_sentinel.analyse import read_tunnels

        for manifest_path in MANIFESTS:
            intent = json.loads(manifest_path.read_text())["intent"]
            if intent["integrity"] is not None:
                continue
            tunnels = [
                t for t in read_tunnels(manifest_path.parent / "capture_outer.pcap") if t.ike
            ]
            if not tunnels:
                continue
            recovered = config_from_exchange(tunnels[0].ike)  # type: ignore[arg-type]
            assert recovered.ok, recovered.reason
            assert recovered.config is not None
            assert recovered.config.integrity is None
            return
        pytest.skip("no AEAD configuration in the sampled corpus")

    def test_a_recovered_configuration_can_be_hardened(self) -> None:
        """The point of the exercise: a capture in, a change package out."""
        from ipsec_sentinel.analyse import read_tunnels
        from ipsec_sentinel.remediate.generators.strongswan import generate_change_package

        for manifest_path in MANIFESTS:
            tunnels = [
                t for t in read_tunnels(manifest_path.parent / "capture_outer.pcap") if t.ike
            ]
            if not tunnels:
                continue
            recovered = config_from_exchange(tunnels[0].ike)  # type: ignore[arg-type]
            if not recovered.ok or recovered.config is None:
                continue
            from ipsec_sentinel.remediate.generators.strongswan import harden

            _, changes = harden(recovered.config)
            if not changes:
                continue
            package = generate_change_package("t1", recovered.config, ["CRY-05"])
            assert package.local_config.content
            assert package.peer_config.content
            return
        pytest.skip("no correctable configuration in the sampled corpus")


# IKEv1 phase 1, whose algorithm numbers are a different registry entirely: value 5 is
# 3DES here and DES-IV32 in IKEv2, and the hash serves as both integrity and PRF.
IKEV1_3DES_MD5_MODP1024 = proposal(
    [
        transform(TransformType.ENCR, 5, "3DES_CBC"),
        transform(TransformType.INTEG, 1, "MD5"),
        transform(TransformType.DH, 2, "1024-bit MODP"),
    ]
)

IKEV1_AES256_SHA256_MODP2048 = proposal(
    [
        transform(TransformType.ENCR, 7, "AES_CBC", 256),
        transform(TransformType.INTEG, 4, "SHA2_256"),
        transform(TransformType.DH, 14, "2048-bit MODP"),
    ]
)


class TestTheTwoRegistriesAreKeptApart:
    """IKEv1 and IKEv2 number their algorithms differently, and the overlap misleads.

    Value 7 is CAST in IKEv2 and AES in IKEv1; value 5 is DES-IV32 in IKEv2 and 3DES in
    IKEv1. Reading one through the other's table does not fail — it yields a different,
    plausible algorithm, and the change package built from it would correct a
    configuration the device does not have. Found by running the corpus, which contains
    IKEv1 captures.
    """

    def test_an_ikev1_proposal_reads_as_ikev1(self) -> None:
        recovered = config_from_proposal(IKEV1_3DES_MD5_MODP1024, ike_version="IKEv1")
        assert recovered.ok, recovered.reason
        assert recovered.config is not None
        assert recovered.config.encryption == "3des"
        assert recovered.config.integrity == "md5"

    def test_the_same_numbers_read_as_ikev2_give_a_different_answer(self) -> None:
        """The whole point: the numbers alone do not identify the algorithm."""
        as_v2 = config_from_proposal(IKEV1_3DES_MD5_MODP1024, ike_version="IKEv2")
        as_v1 = config_from_proposal(IKEV1_3DES_MD5_MODP1024, ike_version="IKEv1")
        assert as_v1.ok
        assert as_v1.config is not None
        # Either IKEv2 refuses value 5, or it resolves it to something else — but never
        # to the same algorithm.
        if as_v2.ok:
            assert as_v2.config is not None
            assert as_v2.config.encryption != as_v1.config.encryption

    def test_ikev1_value_7_is_aes_not_cast(self) -> None:
        recovered = config_from_proposal(IKEV1_AES256_SHA256_MODP2048, ike_version="IKEv1")
        assert recovered.ok, recovered.reason
        assert recovered.config is not None
        assert recovered.config.encryption == "aes256"

    def test_ikev2_value_12_is_aes(self) -> None:
        recovered = config_from_proposal(AES256_SHA256_MODP2048, ike_version="IKEv2")
        assert recovered.config is not None
        assert recovered.config.encryption == "aes256"

    def test_the_ikev1_hash_serves_as_the_prf(self) -> None:
        """RFC 2409 has no separate PRF attribute; assuming one would invent a setting."""
        recovered = config_from_proposal(IKEV1_3DES_MD5_MODP1024, ike_version="IKEv1")
        assert recovered.config is not None
        assert recovered.config.prf == "prfmd5"
        assert not any("no PRF transform" in a for a in recovered.assumptions)

    def test_an_unknown_ikev1_encryption_names_the_version_in_the_reason(self) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 99, "?"),
                    transform(TransformType.INTEG, 1, "MD5"),
                    transform(TransformType.DH, 2, "1024-bit MODP"),
                ]
            ),
            ike_version="IKEv1",
        )
        assert not recovered.ok
        assert "IKEv1 encryption transform 99" in (recovered.reason or "")


class TestTheMapping:
    def test_key_length_separates_aes_128_from_aes_256(self) -> None:
        """Both are transform ID 12; only the attribute tells them apart."""
        for key_length, expected in ((128, "aes128"), (256, "aes256")):
            recovered = config_from_proposal(
                proposal(
                    [
                        transform(TransformType.ENCR, 12, "ENCR_AES_CBC", key_length),
                        transform(TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
                        transform(TransformType.PRF, 5, "PRF_HMAC_SHA2_256"),
                        transform(TransformType.DH, 14, "2048-bit MODP"),
                    ]
                ),
                ike_version="IKEv2",
            )
            assert recovered.ok
            assert recovered.config is not None
            assert recovered.config.encryption == expected

    def test_aes_without_a_key_length_is_refused(self) -> None:
        """Guessing 128 would silently under-report; guessing 256 would over-report."""
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 12, "ENCR_AES_CBC"),
                    transform(TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
                    transform(TransformType.DH, 14, "2048-bit MODP"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert not recovered.ok
        assert "key length" in (recovered.reason or "")

    def test_an_unknown_encryption_transform_is_refused(self) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 200, "ENCR_UNKNOWN"),
                    transform(TransformType.DH, 14, "2048-bit MODP"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert not recovered.ok
        assert "no configuration equivalent" in (recovered.reason or "")

    def test_an_unknown_dh_group_is_refused(self) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 3, "ENCR_3DES"),
                    transform(TransformType.INTEG, 2, "AUTH_HMAC_SHA1_96"),
                    transform(TransformType.DH, 200, "unknown"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert not recovered.ok
        assert "DH group 200" in (recovered.reason or "")

    def test_a_non_aead_cipher_with_no_integrity_is_refused(self) -> None:
        """3DES with no integrity is a real and dangerous configuration, not a default."""
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 3, "ENCR_3DES"),
                    transform(TransformType.DH, 2, "1024-bit MODP"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert not recovered.ok
        assert "not an AEAD cipher" in (recovered.reason or "")

    def test_a_proposal_with_no_encryption_is_refused(self) -> None:
        recovered = config_from_proposal(
            proposal([transform(TransformType.DH, 14, "2048-bit MODP")]), ike_version="IKEv2"
        )
        assert not recovered.ok
        assert "no encryption transform" in (recovered.reason or "")

    def test_every_group_the_probe_offers_can_be_reconstructed(self) -> None:
        from ipsec_sentinel.probe import DEFAULT_CANDIDATES

        assert {c.dh_group for c in DEFAULT_CANDIDATES} <= set(DH_BY_ID)


class TestAssumptionsAreDeclared:
    def test_what_the_wire_does_not_carry_is_named(self) -> None:
        recovered = config_from_proposal(AES256_SHA256_MODP2048, ike_version="IKEv2")
        assert recovered.ok
        joined = " ".join(recovered.assumptions)
        assert "SA lifetimes are local policy" in joined
        assert "perfect forward secrecy" in joined

    def test_pfs_is_assumed_present_not_absent(self) -> None:
        """Assuming absent would make the generator "enable PFS" on every tunnel.

        Including the ones that already have it — a change an operator would rightly
        refuse, and one that would discredit every other recommendation beside it.
        """
        recovered = config_from_proposal(AES256_SHA256_MODP2048, ike_version="IKEv2")
        assert recovered.config is not None
        assert recovered.config.pfs is True

    def test_the_assumed_lifetimes_are_the_declared_constants(self) -> None:
        recovered = config_from_proposal(AES256_SHA256_MODP2048, ike_version="IKEv2")
        assert recovered.config is not None
        assert recovered.config.ike_lifetime_s == ASSUMED_IKE_LIFETIME_S
        assert recovered.config.child_lifetime_s == ASSUMED_CHILD_LIFETIME_S

    def test_a_missing_prf_is_assumed_and_declared(self) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 12, "ENCR_AES_CBC", 256),
                    transform(TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
                    transform(TransformType.DH, 14, "2048-bit MODP"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert recovered.ok
        assert any("no PRF transform was observed" in a for a in recovered.assumptions)


class TestFromAnExchange:
    @staticmethod
    def _exchange(  # type: ignore[no-untyped-def]
        aggressive: bool = False,
        version: str = "IKEv2",
        src: str = "203.0.113.1",
        offered: Proposal | None = None,
    ):
        from datetime import UTC, datetime

        return IKEExchange(
            initiator_spi="1122334455667788",
            responder_spi="99aabbccddeeff00",
            version=version,
            exchange_type="IKE_SA_INIT",
            is_aggressive=aggressive,
            proposals_offered=[offered or AES256_SHA256_MODP2048],
            timestamp=datetime(2026, 6, 1, tzinfo=UTC),
            src_ip=src,
            dst_ip="198.51.100.1",
        )

    def test_an_exchange_with_no_proposal_is_refused(self) -> None:
        exchange = self._exchange()
        exchange.proposals_offered = []
        assert not config_from_exchange(exchange).ok

    def test_aggressive_mode_is_carried_through(self) -> None:
        recovered = config_from_exchange(
            self._exchange(aggressive=True, version="IKEv1", offered=IKEV1_3DES_MD5_MODP1024)
        )
        assert recovered.config is not None, recovered.reason
        assert recovered.config.aggressive is True
        assert recovered.config.ike_version == "ikev1"

    def test_the_ip_version_follows_the_endpoint(self) -> None:
        assert config_from_exchange(self._exchange(src="fd00::1")).config.ip_version == 6  # type: ignore[union-attr]
        assert config_from_exchange(self._exchange()).config.ip_version == 4  # type: ignore[union-attr]

    def test_the_offered_proposal_is_read_not_the_accepted_one(self) -> None:
        """What a peer offers is what it will accept generally; that is what to change."""
        exchange = self._exchange()
        exchange.proposals_offered = [
            proposal(
                [
                    transform(TransformType.ENCR, 3, "ENCR_3DES"),
                    transform(TransformType.INTEG, 1, "AUTH_HMAC_MD5_96"),
                    transform(TransformType.PRF, 1, "PRF_HMAC_MD5"),
                    transform(TransformType.DH, 2, "1024-bit MODP"),
                ]
            ),
            AES256_SHA256_MODP2048,
        ]
        recovered = config_from_exchange(exchange)
        assert recovered.config is not None
        assert recovered.config.encryption == "3des"


class TestEveryGCMIcvLengthIsMapped:
    """RFC 8221 permits an 8-, 12- or 16-octet ICV, and all three are deployed.

    Only 16 was mapped at first, so a device reporting either of the others failed
    reconstruction with "no configuration equivalent". Found by asserting that the
    device-state mapping and the wire mapping agree — neither is authoritative alone.
    """

    @pytest.mark.parametrize(
        ("transform_id", "key_length", "expected"),
        [
            (18, 128, "aes128gcm8"),
            (18, 256, "aes256gcm8"),
            (19, 128, "aes128gcm12"),
            (19, 256, "aes256gcm12"),
            (20, 128, "aes128gcm16"),
            (20, 256, "aes256gcm16"),
        ],
    )
    def test_each_variant_reconstructs(
        self, transform_id: int, key_length: int, expected: str
    ) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, transform_id, "ENCR_AES_GCM", key_length),
                    transform(TransformType.PRF, 5, "PRF_HMAC_SHA2_256"),
                    transform(TransformType.DH, 31, "Curve25519"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert recovered.ok, recovered.reason
        assert recovered.config is not None
        assert recovered.config.encryption == expected
        assert recovered.config.integrity is None, "AEAD carries its own integrity"

    def test_an_unmappable_gcm_key_length_names_the_icv(self) -> None:
        recovered = config_from_proposal(
            proposal(
                [
                    transform(TransformType.ENCR, 18, "ENCR_AES_GCM", 512),
                    transform(TransformType.DH, 31, "Curve25519"),
                ]
            ),
            ike_version="IKEv2",
        )
        assert not recovered.ok
        assert "AES-GCM-8" in (recovered.reason or "")

    def test_every_mapped_name_is_a_configuration_the_matrix_accepts(self) -> None:
        """A name this maps to that TunnelConfig rejects would fail only at construction."""
        from ipsec_sentinel.remediate.observed import AES_GCM_BY_KEY_LENGTH
        from testbed.orchestrate.config_gen import AEAD_ENCRYPTIONS

        names = {n for by_length in AES_GCM_BY_KEY_LENGTH.values() for n in by_length.values()}
        assert names <= AEAD_ENCRYPTIONS

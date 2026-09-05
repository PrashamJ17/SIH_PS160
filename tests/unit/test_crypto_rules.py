"""Tests for cryptographic strength rules CRY-01..CRY-10 (build plan Step 6.2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.rules.crypto import (
    BASELINE_STRICT,
    CRY_01,
    CRY_02,
    CRY_03,
    CRY_04,
    CRY_05,
    CRY_06,
    CRY_07,
    CRY_08,
    CRY_09,
    CRY_10,
    CRYPTO_RULES,
)
from ipsec_sentinel.models import IKEExchange, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.parser.correlate import Tunnel, correlate

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
ZERO = "00" * 8


def encr(id_: int, name: str, key_length: int | None = None) -> Transform:
    return Transform(type=TransformType.ENCR, id=id_, name=name, key_length=key_length)


def integ(id_: int, name: str) -> Transform:
    return Transform(type=TransformType.INTEG, id=id_, name=name)


def dh(id_: int, name: str) -> Transform:
    return Transform(type=TransformType.DH, id=id_, name=name)


AES_GCM_256 = encr(20, "ENCR_AES_GCM_16", 256)
AES_CBC_256 = encr(12, "ENCR_AES_CBC", 256)
AES_CBC_128 = encr(12, "ENCR_AES_CBC", 128)
DES = encr(2, "ENCR_DES", 56)
TRIPLE_DES = encr(3, "ENCR_3DES")
SHA256 = integ(12, "AUTH_HMAC_SHA2_256_128")
MD5 = integ(1, "AUTH_HMAC_MD5_96")
SHA1 = integ(2, "AUTH_HMAC_SHA1_96")
INTEG_NONE = integ(0, "NONE")
ECP256 = dh(19, "256-bit ECP")
MODP768 = dh(1, "768-bit MODP")
MODP1024 = dh(2, "1024-bit MODP")
MODP1536 = dh(5, "1536-bit MODP")
MODP2048 = dh(14, "2048-bit MODP")

STRONG = [AES_GCM_256, SHA256, ECP256]


def proposal(transforms: list[Transform], number: int = 1) -> Proposal:
    return Proposal(number=number, protocol="IKE", transforms=transforms)


def tunnel_with(
    proposals: list[Proposal], accepted: Proposal | None = None, offset_s: float = 0.0
) -> Tunnel:
    """A tunnel whose initiator offered `proposals`, with an optional responder reply."""
    offer = IKEExchange(
        initiator_spi="11" * 8,
        responder_spi=ZERO,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        proposals_offered=proposals,
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )
    messages = [offer]
    if accepted is not None:
        messages.append(
            IKEExchange(
                initiator_spi="11" * 8,
                responder_spi="22" * 8,
                version="IKEv2",
                exchange_type="IKE_SA_INIT",
                proposals_offered=[accepted],
                timestamp=BASE + timedelta(seconds=offset_s + 0.1),
                src_ip="192.0.2.2",
                dst_ip="192.0.2.1",
            )
        )
    return correlate(messages, [])[0]


STRONG_TUNNEL = tunnel_with([proposal(STRONG)], accepted=proposal(STRONG))


class TestEachRuleHasAPositiveAndNegativeCase:
    @pytest.mark.parametrize(
        ("rule", "weak", "severity"),
        [
            (CRY_01, [AES_GCM_256, SHA256, MODP768], Severity.CRITICAL),
            (CRY_02, [AES_GCM_256, SHA256, MODP1024], Severity.CRITICAL),
            (CRY_03, [AES_GCM_256, SHA256, MODP1536], Severity.HIGH),
            (CRY_04, [DES, SHA256, ECP256], Severity.CRITICAL),
            (CRY_05, [TRIPLE_DES, SHA256, ECP256], Severity.CRITICAL),
            (CRY_06, [AES_GCM_256, MD5, ECP256], Severity.HIGH),
            (CRY_07, [AES_GCM_256, SHA1, ECP256], Severity.HIGH),
            (CRY_08, [AES_CBC_256, INTEG_NONE, ECP256], Severity.HIGH),
            (CRY_09, [DES, SHA256, ECP256], Severity.HIGH),
        ],
        ids=lambda v: v.id if hasattr(v, "id") else "",
    )
    def test_the_rule_fires_on_its_own_weakness(
        self, rule, weak: list[Transform], severity: Severity
    ) -> None:  # type: ignore[no-untyped-def]
        finding = rule.evaluate(tunnel_with([proposal(weak)]))
        assert finding is not None, f"{rule.id} did not fire"
        assert finding.rule_id == rule.id
        assert finding.severity is severity
        assert finding.confidence is None

    @pytest.mark.parametrize(
        "rule",
        [CRY_01, CRY_02, CRY_03, CRY_04, CRY_05, CRY_06, CRY_07, CRY_08, CRY_09],
        ids=lambda r: r.id,
    )
    def test_the_rule_is_silent_on_a_strong_proposal(self, rule) -> None:  # type: ignore[no-untyped-def]
        assert rule.evaluate(STRONG_TUNNEL) is None


class TestSpecificBehaviour:
    def test_cry_01_does_not_fire_on_a_different_group(self) -> None:
        assert CRY_01.evaluate(tunnel_with([proposal([AES_GCM_256, MODP1024])])) is None

    def test_cry_05_does_not_fire_on_plain_des(self) -> None:
        """Distinct rules with distinct remediation; conflating them loses that."""
        assert CRY_05.evaluate(tunnel_with([proposal([DES, SHA256])])) is None

    def test_cry_04_does_not_fire_on_3des(self) -> None:
        assert CRY_04.evaluate(tunnel_with([proposal([TRIPLE_DES, SHA256])])) is None

    def test_cry_08_is_silent_when_cbc_has_integrity(self) -> None:
        assert CRY_08.evaluate(tunnel_with([proposal([AES_CBC_256, SHA256])])) is None

    def test_cry_08_is_silent_for_aead_without_an_integrity_transform(self) -> None:
        """AEAD carries integrity internally; flagging it is a false positive."""
        assert CRY_08.evaluate(tunnel_with([proposal([AES_GCM_256, ECP256])])) is None

    def test_cry_08_fires_when_the_integrity_transform_is_none(self) -> None:
        finding = CRY_08.evaluate(tunnel_with([proposal([AES_CBC_256, INTEG_NONE])]))
        assert finding is not None
        assert "no integrity transform" in finding.evidence

    def test_cry_09_is_silent_on_a_128_bit_key(self) -> None:
        """128 is the minimum, not below it."""
        assert CRY_09.evaluate(tunnel_with([proposal([AES_CBC_128, SHA256])])) is None

    def test_cry_09_is_silent_when_no_key_length_was_stated(self) -> None:
        """An absent key length is unknown, not short — guessing would be a false positive."""
        assert CRY_09.evaluate(tunnel_with([proposal([TRIPLE_DES, SHA256])])) is None

    def test_cry_10_fires_on_aes_128_and_cry_09_does_not(self) -> None:
        weak = tunnel_with([proposal([AES_CBC_128, SHA256, ECP256])])
        assert CRY_10.evaluate(weak) is not None
        assert CRY_09.evaluate(weak) is None

    def test_cry_10_is_only_in_the_strict_baseline(self) -> None:
        """AES-128 is not broken; the finding exists only where a policy demands 256."""
        assert CRY_10.baselines == [BASELINE_STRICT]
        assert DEFAULT_BASELINE not in CRY_10.baselines


class TestEveryProposalIsChecked:
    """The behaviour that separates a useful assessment from a reassuring one."""

    def test_a_weak_fallback_fires_even_when_a_strong_proposal_is_first(self) -> None:
        tunnel = tunnel_with(
            [proposal(STRONG, number=1), proposal([TRIPLE_DES, SHA256, MODP1024], number=2)],
            accepted=proposal(STRONG),
        )
        assert CRY_05.evaluate(tunnel) is not None
        assert CRY_02.evaluate(tunnel) is not None

    def test_the_evidence_names_the_proposal_and_the_total(self) -> None:
        tunnel = tunnel_with(
            [proposal(STRONG, number=1), proposal([TRIPLE_DES, SHA256], number=2)],
            accepted=proposal(STRONG),
        )
        finding = CRY_05.evaluate(tunnel)
        assert finding is not None
        assert "proposal 2 of 2" in finding.evidence

    def test_offered_but_not_accepted_says_so(self) -> None:
        """The plan's explicit wording requirement."""
        tunnel = tunnel_with(
            [proposal(STRONG, number=1), proposal([TRIPLE_DES, SHA256], number=2)],
            accepted=proposal(STRONG),
        )
        finding = CRY_05.evaluate(tunnel)
        assert finding is not None
        assert "not selected in this session" in finding.evidence

    def test_the_accepted_proposal_is_marked_selected(self) -> None:
        weak = proposal([TRIPLE_DES, SHA256, ECP256])
        finding = CRY_05.evaluate(tunnel_with([weak], accepted=weak))
        assert finding is not None
        assert "selected in this session" in finding.evidence
        assert "not selected" not in finding.evidence

    def test_selection_is_unknown_when_the_reply_was_not_captured(self) -> None:
        """A capture that started late must not assert what it never saw."""
        finding = CRY_05.evaluate(tunnel_with([proposal([TRIPLE_DES, SHA256])]))
        assert finding is not None
        assert "selection unknown" in finding.evidence

    def test_one_finding_covers_every_matching_proposal(self) -> None:
        tunnel = tunnel_with(
            [proposal([TRIPLE_DES, SHA256], number=1), proposal([TRIPLE_DES, MD5], number=2)]
        )
        finding = CRY_05.evaluate(tunnel)
        assert finding is not None
        assert "proposal 1 of 2" in finding.evidence
        assert "proposal 2 of 2" in finding.evidence


WEAK = [TRIPLE_DES, MD5, MODP1024]


class TestFixtureExpectations:
    """The plan's named acceptance cases."""

    def test_the_weak_fixture_triggers_cry_02_cry_05_and_cry_06(self) -> None:
        registry = RuleRegistry()
        for rule in CRYPTO_RULES:
            registry.register(rule)
        tunnel = tunnel_with([proposal(WEAK)])
        fired = {f.rule_id for f in registry.evaluate_all(tunnel, DEFAULT_BASELINE)}
        assert {"CRY-02", "CRY-05", "CRY-06"} <= fired

    def test_the_strong_fixture_triggers_none_of_cry_01_to_cry_09(self) -> None:
        registry = RuleRegistry()
        for rule in CRYPTO_RULES:
            registry.register(rule)
        fired = {f.rule_id for f in registry.evaluate_all(STRONG_TUNNEL, DEFAULT_BASELINE)}
        assert fired == set(), f"strong proposal triggered {sorted(fired)}"

    def test_a_3des_fallback_offered_but_not_accepted_still_triggers_cry_05(self) -> None:
        strong = proposal(STRONG, number=1)
        tunnel = tunnel_with([strong, proposal([TRIPLE_DES, SHA256], number=2)], accepted=strong)
        registry = RuleRegistry()
        for rule in CRYPTO_RULES:
            registry.register(rule)
        findings = {f.rule_id: f for f in registry.evaluate_all(tunnel, DEFAULT_BASELINE)}
        assert "CRY-05" in findings
        assert "not selected in this session" in findings["CRY-05"].evidence


class TestRegistryIntegration:
    def test_every_rule_registers_without_a_duplicate_id(self) -> None:
        registry = RuleRegistry()
        for rule in CRYPTO_RULES:
            registry.register(rule)
        assert len(registry) == 10

    def test_every_finding_is_deterministic(self) -> None:
        registry = RuleRegistry()
        for rule in CRYPTO_RULES:
            registry.register(rule)
        tunnel = tunnel_with([proposal([DES, MD5, MODP768])])
        findings = registry.evaluate_all(tunnel, DEFAULT_BASELINE)
        assert findings
        assert all(f.confidence is None for f in findings)

    def test_every_rule_carries_a_standard_reference_and_remediation(self) -> None:
        """A finding without a citation is an opinion; without remediation, a complaint."""
        for rule in CRYPTO_RULES:
            assert rule.standard_ref, rule.id
            assert rule.remediation_hint, rule.id

    def test_no_rule_fires_on_a_tunnel_with_no_ike(self) -> None:
        orphan = Tunnel(tunnel_id="x", endpoints=("192.0.2.1", "192.0.2.2"))
        for rule in CRYPTO_RULES:
            assert rule.evaluate(orphan) is None, rule.id

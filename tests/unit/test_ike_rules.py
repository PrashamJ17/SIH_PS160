"""Tests for IKE configuration rules IKE-01..IKE-04 (build plan Step 6.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.rules.ike import (
    IKE_01,
    IKE_02,
    IKE_03,
    IKE_04,
    IKE_RULES,
    PSK_EXPOSURE_STATEMENT,
)
from ipsec_sentinel.models import IKEExchange, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.parser.correlate import Tunnel, correlate

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
ZERO = "00" * 8

STRONG = [
    Transform(type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256),
    Transform(type=TransformType.INTEG, id=12, name="AUTH_HMAC_SHA2_256_128"),
    Transform(type=TransformType.DH, id=19, name="256-bit ECP"),
]
WEAK = [
    Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES"),
    Transform(type=TransformType.INTEG, id=1, name="AUTH_HMAC_MD5_96"),
    Transform(type=TransformType.DH, id=2, name="1024-bit MODP"),
]


def proposal(transforms: list[Transform], number: int = 1) -> Proposal:
    return Proposal(number=number, protocol="IKE", transforms=transforms)


def build(
    version: str = "IKEv2",
    exchange_type: str = "IKE_SA_INIT",
    aggressive: bool = False,
    auth_methods: list[str] | None = None,
    proposals: list[Proposal] | None = None,
    accepted: Proposal | None = None,
) -> Tunnel:
    offer = IKEExchange(
        initiator_spi="11" * 8,
        responder_spi=ZERO,
        version=version,
        exchange_type=exchange_type,
        is_aggressive=aggressive,
        auth_methods=auth_methods or [],
        proposals_offered=proposals or [proposal(STRONG)],
        timestamp=BASE,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )
    messages = [offer]
    if accepted is not None:
        messages.append(
            IKEExchange(
                initiator_spi="11" * 8,
                responder_spi="22" * 8,
                version=version,
                exchange_type=exchange_type,
                is_aggressive=aggressive,
                auth_methods=auth_methods or [],
                proposals_offered=[accepted],
                timestamp=BASE + timedelta(seconds=0.1),
                src_ip="192.0.2.2",
                dst_ip="192.0.2.1",
            )
        )
    return correlate(messages, [])[0]


def registry() -> RuleRegistry:
    reg = RuleRegistry()
    for rule in IKE_RULES:
        reg.register(rule)
    return reg


class TestIKE01:
    def test_it_fires_on_ikev1(self) -> None:
        finding = IKE_01.evaluate(build(version="IKEv1", exchange_type="Main Mode"))
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is None

    def test_it_is_silent_on_ikev2(self) -> None:
        assert IKE_01.evaluate(build()) is None

    def test_the_evidence_names_the_endpoints(self) -> None:
        finding = IKE_01.evaluate(build(version="IKEv1"))
        assert finding is not None
        assert "192.0.2.1" in finding.evidence and "192.0.2.2" in finding.evidence


class TestIKE02:
    def test_it_fires_on_aggressive_mode_without_psk(self) -> None:
        finding = IKE_02.evaluate(
            build(
                version="IKEv1",
                exchange_type="Aggressive Mode",
                aggressive=True,
                auth_methods=["RSA_SIGNATURES"],
            )
        )
        assert finding is not None
        assert finding.severity is Severity.HIGH

    def test_it_is_silent_on_main_mode(self) -> None:
        assert IKE_02.evaluate(build(version="IKEv1", exchange_type="Main Mode")) is None

    def test_it_is_silent_on_ikev2(self) -> None:
        assert IKE_02.evaluate(build()) is None


class TestIKE03:
    @staticmethod
    def _aggressive_psk() -> Tunnel:
        return build(
            version="IKEv1",
            exchange_type="Aggressive Mode",
            aggressive=True,
            auth_methods=["PRE_SHARED_KEY"],
        )

    def test_it_fires_on_aggressive_mode_with_psk(self) -> None:
        finding = IKE_03.evaluate(self._aggressive_psk())
        assert finding is not None
        assert finding.severity is Severity.CRITICAL

    def test_the_evidence_carries_the_required_statement_verbatim(self) -> None:
        """The sentence an operator acts on; a paraphrase would soften it."""
        finding = IKE_03.evaluate(self._aggressive_psk())
        assert finding is not None
        assert PSK_EXPOSURE_STATEMENT in finding.evidence
        assert "Treat this PSK as compromised." in finding.evidence

    def test_it_is_silent_on_aggressive_mode_with_certificates(self) -> None:
        assert (
            IKE_03.evaluate(
                build(
                    version="IKEv1",
                    exchange_type="Aggressive Mode",
                    aggressive=True,
                    auth_methods=["RSA_SIGNATURES"],
                )
            )
            is None
        )

    def test_it_is_silent_on_psk_in_main_mode(self) -> None:
        """Main Mode completes DH before authenticating, so the hash is protected."""
        assert (
            IKE_03.evaluate(
                build(version="IKEv1", exchange_type="Main Mode", auth_methods=["PRE_SHARED_KEY"])
            )
            is None
        )

    def test_the_remediation_says_rotating_alone_is_not_enough(self) -> None:
        assert "only restarts the clock" in IKE_03.remediation_hint


class TestSupersession:
    """IKE-03 supersedes IKE-02: one problem, one finding."""

    def test_only_the_critical_finding_fires_when_psk_is_used(self) -> None:
        tunnel = build(
            version="IKEv1",
            exchange_type="Aggressive Mode",
            aggressive=True,
            auth_methods=["PRE_SHARED_KEY"],
        )
        fired = {f.rule_id for f in registry().evaluate_all(tunnel, DEFAULT_BASELINE)}
        assert "IKE-03" in fired
        assert "IKE-02" not in fired, "two findings invite fixing the cheaper one"

    def test_ike_02_still_fires_without_a_psk(self) -> None:
        tunnel = build(
            version="IKEv1",
            exchange_type="Aggressive Mode",
            aggressive=True,
            auth_methods=["RSA_SIGNATURES"],
        )
        fired = {f.rule_id for f in registry().evaluate_all(tunnel, DEFAULT_BASELINE)}
        assert "IKE-02" in fired
        assert "IKE-03" not in fired

    def test_ike_01_fires_alongside_either(self) -> None:
        """The version finding is a separate problem with separate remediation."""
        tunnel = build(
            version="IKEv1",
            exchange_type="Aggressive Mode",
            aggressive=True,
            auth_methods=["PRE_SHARED_KEY"],
        )
        fired = {f.rule_id for f in registry().evaluate_all(tunnel, DEFAULT_BASELINE)}
        assert {"IKE-01", "IKE-03"} <= fired


class TestIKE04:
    def test_it_fires_when_a_weaker_proposal_was_offered_and_not_chosen(self) -> None:
        strong = proposal(STRONG, number=1)
        tunnel = build(proposals=[strong, proposal(WEAK, number=2)], accepted=strong)
        finding = IKE_04.evaluate(tunnel)
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert "proposal 2 of 2" in finding.evidence

    def test_the_evidence_names_the_specific_weaknesses(self) -> None:
        strong = proposal(STRONG, number=1)
        finding = IKE_04.evaluate(
            build(proposals=[strong, proposal(WEAK, number=2)], accepted=strong)
        )
        assert finding is not None
        assert "ENCR_3DES" in finding.evidence
        assert "AUTH_HMAC_MD5_96" in finding.evidence

    def test_it_is_silent_when_every_offer_is_strong(self) -> None:
        strong = proposal(STRONG, number=1)
        other = proposal(STRONG, number=2)
        assert IKE_04.evaluate(build(proposals=[strong, other], accepted=strong)) is None

    def test_it_is_silent_with_a_single_proposal(self) -> None:
        """With one offer there is nothing to downgrade to; the CRY rules cover it."""
        weak = proposal(WEAK)
        assert IKE_04.evaluate(build(proposals=[weak], accepted=weak)) is None

    def test_it_does_not_fire_on_the_accepted_proposal_itself(self) -> None:
        weak = proposal(WEAK, number=1)
        tunnel = build(proposals=[weak, proposal(STRONG, number=2)], accepted=weak)
        assert IKE_04.evaluate(tunnel) is None

    def test_it_uses_the_same_notion_of_weak_as_the_crypto_rules(self) -> None:
        """Two independent definitions of "weak" is a defect an auditor finds at once."""
        from ipsec_sentinel.assess.rules.crypto import weaknesses_in

        assert "ENCR_3DES" in weaknesses_in(proposal(WEAK))
        assert weaknesses_in(proposal(STRONG)) == []


class TestGeneralProperties:
    def test_all_rules_register_cleanly(self) -> None:
        assert len(registry()) == 4

    def test_no_rule_fires_on_an_orphan_tunnel(self) -> None:
        orphan = Tunnel(tunnel_id="x", endpoints=("192.0.2.1", "192.0.2.2"))
        for rule in IKE_RULES:
            assert rule.evaluate(orphan) is None, rule.id

    def test_every_finding_is_deterministic(self) -> None:
        tunnel = build(
            version="IKEv1",
            exchange_type="Aggressive Mode",
            aggressive=True,
            auth_methods=["PRE_SHARED_KEY"],
        )
        findings = registry().evaluate_all(tunnel, DEFAULT_BASELINE)
        assert findings
        assert all(f.confidence is None for f in findings)

    def test_every_rule_carries_a_citation_and_remediation(self) -> None:
        for rule in IKE_RULES:
            assert rule.standard_ref, rule.id
            assert rule.remediation_hint, rule.id

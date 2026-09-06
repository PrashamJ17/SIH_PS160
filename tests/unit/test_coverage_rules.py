"""Tests for coverage and disclosure rules ESP-01, ESP-02, OPS-01, and CRY-12.

These four exist because the build plan names 20 rule IDs while the M6 gate requires
26. Rather than pad the count, each fills a gap the other rules genuinely leave: an
unassessable tunnel, a tunnel that carries nothing, an implementation announcing itself
in cleartext, and NULL encryption — which no rule checked for at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.rules.coverage import (
    COVERAGE_RULES,
    ESP_01,
    ESP_02,
    OPS_01,
)
from ipsec_sentinel.assess.rules.crypto import CRY_12
from ipsec_sentinel.models import IKEExchange, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.parser.correlate import Tunnel, correlate
from ipsec_sentinel.parser.esp import AssembledFlow

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def exchange(vendor_ids: list[str] | None = None, offset_s: float = 0.0) -> IKEExchange:
    return IKEExchange(
        initiator_spi="11" * 8,
        responder_spi="00" * 8,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        vendor_ids=vendor_ids or [],
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )


def flow(spi: str = "deadbeef", packets: int = 10, offset_s: float = 1.0) -> AssembledFlow:
    start = BASE + timedelta(seconds=offset_s)
    return AssembledFlow(
        spi=spi,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
        sizes=[100] * packets,
        sequences=list(range(1, packets + 1)),
        timestamps=[start + timedelta(milliseconds=i) for i in range(packets)],
    )


class TestESP01:
    def test_it_fires_on_esp_with_no_negotiation(self) -> None:
        tunnel = correlate([], [flow()])[0]
        finding = ESP_01.evaluate(tunnel)
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is None

    def test_the_evidence_says_the_tunnel_is_unexamined_not_clean(self) -> None:
        """A silent orphan in a report invites the reader to assume it was checked."""
        finding = ESP_01.evaluate(correlate([], [flow()])[0])
        assert finding is not None
        assert "not assessed" in finding.evidence
        assert "unexamined" in finding.evidence

    def test_the_evidence_names_the_spi_and_volume(self) -> None:
        finding = ESP_01.evaluate(correlate([], [flow(spi="a1b2c3d4", packets=7)])[0])
        assert finding is not None
        assert "a1b2c3d4" in finding.evidence
        assert "7 ESP packets" in finding.evidence

    def test_it_is_silent_when_a_negotiation_was_seen(self) -> None:
        assert ESP_01.evaluate(correlate([exchange()], [flow()])[0]) is None

    def test_it_is_silent_on_a_tunnel_with_no_flows(self) -> None:
        assert ESP_01.evaluate(Tunnel(tunnel_id="x", endpoints=("a", "b"))) is None


class TestESP02:
    def test_it_fires_on_a_negotiation_with_no_traffic(self) -> None:
        finding = ESP_02.evaluate(correlate([exchange()], [])[0])
        assert finding is not None
        assert finding.severity is Severity.LOW

    def test_the_evidence_offers_both_explanations(self) -> None:
        """Failed and idle need different responses; the tool cannot tell which."""
        finding = ESP_02.evaluate(correlate([exchange()], [])[0])
        assert finding is not None
        assert "failed to establish" in finding.evidence
        assert "idle" in finding.evidence

    def test_it_is_silent_when_traffic_was_carried(self) -> None:
        assert ESP_02.evaluate(correlate([exchange()], [flow()])[0]) is None

    def test_it_is_silent_on_an_orphan(self) -> None:
        """ESP-01 and ESP-02 describe opposite absences and must never both fire."""
        orphan = correlate([], [flow()])[0]
        assert ESP_02.evaluate(orphan) is None
        assert ESP_01.evaluate(orphan) is not None


class TestOPS01:
    @staticmethod
    def _with_vendor(text: str) -> Tunnel:
        return correlate([exchange(vendor_ids=[text.encode().hex()])], [])[0]

    def test_it_fires_on_a_cleartext_implementation_name(self) -> None:
        finding = OPS_01.evaluate(self._with_vendor("strongSwan 5.9.8"))
        assert finding is not None
        assert "strongSwan 5.9.8" in finding.evidence
        assert finding.severity is Severity.LOW

    def test_it_is_silent_on_an_opaque_vendor_id(self) -> None:
        """A hash fingerprints too, but reporting every VID buries the readable ones."""
        opaque = correlate([exchange(vendor_ids=["afcad71368a1f1c96b8696fc77570100"])], [])[0]
        assert OPS_01.evaluate(opaque) is None

    def test_it_is_silent_when_no_vendor_id_was_sent(self) -> None:
        assert OPS_01.evaluate(correlate([exchange()], [])[0]) is None

    def test_duplicate_vendor_ids_are_reported_once(self) -> None:
        vid = b"strongSwan".hex()
        tunnel = correlate(
            [exchange(vendor_ids=[vid], offset_s=0), exchange(vendor_ids=[vid], offset_s=1)],
            [],
        )[0]
        finding = OPS_01.evaluate(tunnel)
        assert finding is not None
        assert finding.evidence.count("strongSwan") == 1

    def test_the_remediation_frames_it_as_defence_in_depth(self) -> None:
        assert "defence in depth rather than a vulnerability" in OPS_01.remediation_hint

    def test_it_is_silent_on_an_orphan_tunnel(self) -> None:
        assert OPS_01.evaluate(Tunnel(tunnel_id="x", endpoints=("a", "b"))) is None


class TestCRY12:
    @staticmethod
    def _tunnel(encr_id: int, name: str) -> Tunnel:
        message = IKEExchange(
            initiator_spi="11" * 8,
            responder_spi="00" * 8,
            version="IKEv2",
            exchange_type="IKE_SA_INIT",
            proposals_offered=[
                Proposal(
                    number=1,
                    protocol="IKE",
                    transforms=[Transform(type=TransformType.ENCR, id=encr_id, name=name)],
                )
            ],
            timestamp=BASE,
            src_ip="192.0.2.1",
            dst_ip="192.0.2.2",
        )
        return correlate([message], [])[0]

    def test_it_fires_on_null_encryption(self) -> None:
        finding = CRY_12.evaluate(self._tunnel(11, "ENCR_NULL"))
        assert finding is not None
        assert finding.severity is Severity.CRITICAL

    def test_it_is_silent_on_real_encryption(self) -> None:
        assert CRY_12.evaluate(self._tunnel(20, "ENCR_AES_GCM_16")) is None

    def test_the_remediation_explains_why_it_is_worse_than_no_tunnel(self) -> None:
        assert "worse than no tunnel" in CRY_12.remediation_hint


class TestRegistration:
    def test_all_coverage_rules_register_cleanly(self) -> None:
        registry = RuleRegistry()
        for rule in COVERAGE_RULES:
            registry.register(rule)
        assert len(registry) == 3

    def test_every_rule_carries_a_citation_and_remediation(self) -> None:
        for rule in [*COVERAGE_RULES, CRY_12]:
            assert rule.standard_ref, rule.id
            assert rule.remediation_hint, rule.id

    def test_every_finding_is_deterministic(self) -> None:
        registry = RuleRegistry()
        for rule in COVERAGE_RULES:
            registry.register(rule)
        findings = registry.evaluate_all(correlate([], [flow()])[0], DEFAULT_BASELINE)
        assert findings
        assert all(f.confidence is None for f in findings)

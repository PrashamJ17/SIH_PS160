"""Tests for IKE-to-ESP tunnel correlation (build plan Step 5.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ipsec_sentinel.models import IKEExchange
from ipsec_sentinel.parser.correlate import (
    correlate,
    endpoint_pair,
    group_negotiations,
)
from ipsec_sentinel.parser.esp import AssembledFlow, assemble_esp_flows, extract_esp_packets
from ipsec_sentinel.parser.pcap import extract_ike_exchanges

BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
LEFT = "192.0.2.1"
RIGHT = "192.0.2.2"


def ike(
    initiator_spi: str = "11" * 8,
    offset_s: float = 0.0,
    src: str = LEFT,
    dst: str = RIGHT,
    exchange_type: str = "IKE_SA_INIT",
) -> IKEExchange:
    return IKEExchange(
        initiator_spi=initiator_spi,
        responder_spi="22" * 8,
        version="IKEv2",
        exchange_type=exchange_type,
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=src,
        dst_ip=dst,
    )


def esp(
    spi: str = "aaaaaaaa",
    src: str = LEFT,
    dst: str = RIGHT,
    offset_s: float = 1.0,
    packets: int = 10,
) -> AssembledFlow:
    start = BASE + timedelta(seconds=offset_s)
    return AssembledFlow(
        spi=spi,
        src_ip=src,
        dst_ip=dst,
        sizes=[100] * packets,
        sequences=list(range(1, packets + 1)),
        timestamps=[start + timedelta(milliseconds=i) for i in range(packets)],
    )


class TestEndpointPair:
    def test_the_pair_is_direction_independent(self) -> None:
        assert endpoint_pair(LEFT, RIGHT) == endpoint_pair(RIGHT, LEFT)

    def test_the_pair_is_sorted(self) -> None:
        assert endpoint_pair(RIGHT, LEFT) == (LEFT, RIGHT)


class TestNegotiationGrouping:
    def test_messages_of_one_exchange_group_into_one_negotiation(self) -> None:
        """A single IKEv2 setup is at least four messages, not four tunnels."""
        messages = [
            ike(offset_s=0.0, exchange_type="IKE_SA_INIT"),
            ike(offset_s=0.1, src=RIGHT, dst=LEFT, exchange_type="IKE_SA_INIT"),
            ike(offset_s=0.2, exchange_type="IKE_AUTH"),
            ike(offset_s=0.3, src=RIGHT, dst=LEFT, exchange_type="IKE_AUTH"),
        ]
        negotiations = group_negotiations(messages)
        assert len(negotiations) == 1
        assert len(negotiations[0].messages) == 4

    def test_different_initiator_spis_are_different_negotiations(self) -> None:
        negotiations = group_negotiations(
            [ike(initiator_spi="11" * 8), ike(initiator_spi="33" * 8, offset_s=60)]
        )
        assert len(negotiations) == 2

    def test_the_negotiation_starts_at_its_earliest_message(self) -> None:
        negotiations = group_negotiations([ike(offset_s=5.0), ike(offset_s=0.0)])
        assert negotiations[0].started_at == BASE


class TestOneTunnel:
    def test_one_ike_and_two_esp_flows_make_one_tunnel(self) -> None:
        """The two directions of an SA pair belong to the same tunnel."""
        tunnels = correlate(
            [ike()],
            [esp(spi="aaaaaaaa"), esp(spi="bbbbbbbb", src=RIGHT, dst=LEFT)],
        )
        assert len(tunnels) == 1
        assert len(tunnels[0].flows) == 2
        assert tunnels[0].is_orphan is False
        assert tunnels[0].negotiation_only is False

    def test_the_tunnel_totals_both_directions(self) -> None:
        tunnels = correlate(
            [ike()],
            [esp(packets=10), esp(spi="bbbbbbbb", src=RIGHT, dst=LEFT, packets=5)],
        )
        assert tunnels[0].packet_count == 15
        assert tunnels[0].byte_count == 1500

    def test_the_tunnel_reads_the_offer_not_the_choice(self) -> None:
        """The initiator's full offer is the attack surface; the choice understates it."""
        offer = ike(offset_s=0.0)
        from ipsec_sentinel.models import Proposal, Transform, TransformType

        offer = offer.model_copy(
            update={
                "proposals_offered": [
                    Proposal(
                        number=1,
                        protocol="IKE",
                        transforms=[Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES")],
                    )
                ]
            }
        )
        later = ike(offset_s=0.2, exchange_type="IKE_AUTH")
        tunnels = correlate([later, offer], [esp()])
        assert tunnels[0].ike is not None
        assert tunnels[0].ike.proposals_offered, "the message with proposals must win"


class TestTemporalSeparation:
    def test_two_negotiations_between_the_same_pair_make_two_tunnels(self) -> None:
        tunnels = correlate(
            [ike(initiator_spi="11" * 8, offset_s=0), ike(initiator_spi="33" * 8, offset_s=60)],
            [],
        )
        assert len(tunnels) == 2
        assert tunnels[0].tunnel_id != tunnels[1].tunnel_id

    def test_a_flow_attaches_to_the_most_recent_prior_negotiation(self) -> None:
        """A rekey falls out of causality: later flows belong to the newer SA."""
        tunnels = correlate(
            [ike(initiator_spi="11" * 8, offset_s=0), ike(initiator_spi="33" * 8, offset_s=60)],
            [esp(spi="aaaaaaaa", offset_s=10), esp(spi="cccccccc", offset_s=70)],
        )
        by_id = {t.tunnel_id: t for t in tunnels}
        assert len(by_id) == 2
        flows_per_tunnel = sorted(len(t.flows) for t in tunnels)
        assert flows_per_tunnel == [1, 1]

    def test_a_flow_never_attaches_to_a_later_negotiation(self) -> None:
        """ESP cannot precede the exchange that produced its keys."""
        tunnels = correlate([ike(offset_s=100)], [esp(offset_s=1)])
        negotiated = [t for t in tunnels if not t.is_orphan]
        assert negotiated[0].flows == []
        assert any(t.is_orphan for t in tunnels)


class TestOrphans:
    def test_esp_with_no_ike_is_an_orphan_tunnel(self) -> None:
        tunnels = correlate([], [esp()])
        assert len(tunnels) == 1
        assert tunnels[0].is_orphan is True
        assert tunnels[0].ike is None
        assert tunnels[0].flows

    def test_orphan_flows_between_one_pair_group_into_one_tunnel(self) -> None:
        tunnels = correlate([], [esp(spi="aaaaaaaa"), esp(spi="bbbbbbbb", src=RIGHT, dst=LEFT)])
        assert len(tunnels) == 1
        assert len(tunnels[0].flows) == 2

    def test_orphans_between_different_pairs_stay_separate(self) -> None:
        tunnels = correlate([], [esp(), esp(src="198.51.100.1", dst="198.51.100.2")])
        assert len(tunnels) == 2

    def test_an_orphan_is_still_measured(self) -> None:
        """A long-lived tunnel nobody renegotiated is exactly what is worth finding."""
        tunnels = correlate([], [esp(packets=42)])
        assert tunnels[0].packet_count == 42
        assert tunnels[0].first_seen is not None


class TestNegotiationOnly:
    def test_ike_with_no_esp_is_flagged(self) -> None:
        tunnels = correlate([ike()], [])
        assert len(tunnels) == 1
        assert tunnels[0].negotiation_only is True
        assert tunnels[0].is_orphan is False

    def test_a_tunnel_with_traffic_is_not_flagged(self) -> None:
        assert correlate([ike()], [esp()])[0].negotiation_only is False

    def test_an_orphan_is_not_negotiation_only(self) -> None:
        """The two flags describe opposite absences and must never both be true."""
        tunnel = correlate([], [esp()])[0]
        assert tunnel.is_orphan is True
        assert tunnel.negotiation_only is False


class TestEmpty:
    def test_no_input_yields_no_tunnels(self) -> None:
        assert correlate([], []) == []


class TestStableIdentity:
    def test_the_same_input_yields_the_same_tunnel_id(self) -> None:
        """An inventory diffed across days must recognise the same tunnel."""
        first = correlate([ike()], [esp()])
        second = correlate([ike()], [esp()])
        assert first[0].tunnel_id == second[0].tunnel_id

    def test_different_endpoints_yield_different_ids(self) -> None:
        a = correlate([ike()], [])[0].tunnel_id
        b = correlate([ike(src="198.51.100.1", dst="198.51.100.2")], [])[0].tunnel_id
        assert a != b


CAPTURES = sorted(Path("data/raw/sweep").glob("*/capture_outer.pcap"))


@pytest.mark.skipif(not CAPTURES, reason="no sweep captures present")
class TestAgainstRealCaptures:
    def test_a_real_capture_correlates_to_exactly_one_tunnel(self) -> None:
        """Each sweep cell is one tunnel between one pair. Anything else is a bug.

        This is the test that would have caught treating each IKE message as its own
        tunnel: a real cell has four to nine messages, so the naive version reports
        four to nine tunnels where there is one.
        """
        pcap = CAPTURES[0]
        tunnels = correlate(
            extract_ike_exchanges(pcap),
            assemble_esp_flows(extract_esp_packets(pcap)),
        )
        assert len(tunnels) == 1, [t.tunnel_id for t in tunnels]

    def test_the_real_tunnel_has_both_a_negotiation_and_traffic(self) -> None:
        pcap = CAPTURES[0]
        tunnel = correlate(
            extract_ike_exchanges(pcap),
            assemble_esp_flows(extract_esp_packets(pcap)),
        )[0]
        assert tunnel.is_orphan is False
        assert tunnel.negotiation_only is False
        assert tunnel.packet_count > 0

    def test_every_capture_correlates_without_error(self) -> None:
        for pcap in CAPTURES[:25]:
            tunnels = correlate(
                extract_ike_exchanges(pcap),
                assemble_esp_flows(extract_esp_packets(pcap)),
            )
            assert tunnels, f"{pcap.parent.name} produced no tunnels"

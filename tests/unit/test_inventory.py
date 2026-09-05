"""Tests for the tunnel inventory (build plan Step 5.5)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ipsec_sentinel.assess.inventory import (
    Inventory,
    InventoryStatus,
    KnownTunnel,
    build_inventory,
    known_from_endpoints,
)
from ipsec_sentinel.models import IKEExchange, Proposal, Transform, TransformType
from ipsec_sentinel.parser.correlate import Tunnel, correlate
from ipsec_sentinel.parser.esp import AssembledFlow, assemble_esp_flows, extract_esp_packets
from ipsec_sentinel.parser.pcap import extract_ike_exchanges

BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)


def exchange(src: str, dst: str, offset_s: float = 0.0, aggressive: bool = False) -> IKEExchange:
    return IKEExchange(
        initiator_spi=f"{abs(hash((src, dst))) % (16**16):016x}",
        responder_spi="22" * 8,
        version="IKEv1" if aggressive else "IKEv2",
        exchange_type="Aggressive Mode" if aggressive else "IKE_SA_INIT",
        is_aggressive=aggressive,
        proposals_offered=[
            Proposal(
                number=1,
                protocol="IKE",
                transforms=[
                    Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=256),
                    Transform(type=TransformType.DH, id=14, name="2048-bit MODP"),
                ],
            )
        ],
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=src,
        dst_ip=dst,
    )


def flow(src: str, dst: str, offset_s: float = 1.0, packets: int = 10) -> AssembledFlow:
    start = BASE + timedelta(seconds=offset_s)
    return AssembledFlow(
        spi="aaaaaaaa",
        src_ip=src,
        dst_ip=dst,
        sizes=[100] * packets,
        sequences=list(range(1, packets + 1)),
        timestamps=[start + timedelta(milliseconds=i) for i in range(packets)],
    )


def tunnels_for(pairs: list[tuple[str, str]]) -> list[Tunnel]:
    exchanges = [exchange(a, b, offset_s=i) for i, (a, b) in enumerate(pairs)]
    flows = [flow(a, b, offset_s=i + 0.5) for i, (a, b) in enumerate(pairs)]
    return correlate(exchanges, flows)


PAIRS = [
    ("192.0.2.1", "192.0.2.2"),
    ("198.51.100.1", "198.51.100.2"),
    ("203.0.113.1", "203.0.113.2"),
    ("192.0.2.10", "192.0.2.20"),
    ("198.51.100.10", "198.51.100.20"),
]


class TestCounting:
    def test_the_inventory_lists_every_distinct_tunnel(self) -> None:
        inventory = build_inventory(tunnels_for(PAIRS))
        assert len(inventory) == 5
        assert len({entry.tunnel_id for entry in inventory.entries}) == 5

    def test_an_empty_input_yields_an_empty_inventory(self) -> None:
        inventory = build_inventory([])
        assert len(inventory) == 0
        assert inventory.undocumented == []

    def test_volume_is_carried_through(self) -> None:
        entry = build_inventory(tunnels_for(PAIRS[:1])).entries[0]
        assert entry.packet_count == 10
        assert entry.byte_count == 1000


class TestUndocumentedDetection:
    def test_three_known_of_five_observed_flags_two(self) -> None:
        """The plan's headline case."""
        inventory = build_inventory(tunnels_for(PAIRS), known=known_from_endpoints(PAIRS[:3]))
        assert len(inventory.undocumented) == 2
        assert all(entry.is_undocumented for entry in inventory.undocumented)

    def test_documented_tunnels_are_marked_documented(self) -> None:
        inventory = build_inventory(tunnels_for(PAIRS), known=known_from_endpoints(PAIRS[:3]))
        documented = [e for e in inventory.entries if e.status is InventoryStatus.DOCUMENTED]
        assert len(documented) == 3

    def test_the_documented_name_and_owner_are_attached(self) -> None:
        known = [KnownTunnel(endpoints=PAIRS[0], name="branch-office", owner="net-ops")]
        entry = build_inventory(tunnels_for(PAIRS[:1]), known=known).entries[0]
        assert entry.documented_name == "branch-office"
        assert entry.documented_owner == "net-ops"

    def test_direction_does_not_affect_matching(self) -> None:
        """A documented list written B-to-A must still match traffic seen A-to-B."""
        reversed_pair = (PAIRS[0][1], PAIRS[0][0])
        inventory = build_inventory(
            tunnels_for(PAIRS[:1]), known=known_from_endpoints([reversed_pair])
        )
        assert inventory.undocumented == []

    def test_a_documented_tunnel_never_observed_is_reported(self) -> None:
        """Either decommissioned and never removed from the list, or down right now."""
        inventory = build_inventory(tunnels_for(PAIRS[:2]), known=known_from_endpoints(PAIRS))
        assert len(inventory.unobserved) == 3

    def test_everything_undocumented_when_the_known_list_is_empty(self) -> None:
        inventory = build_inventory(tunnels_for(PAIRS), known=[])
        assert len(inventory.undocumented) == 5


class TestNoKnownList:
    def test_nothing_is_flagged_and_everything_is_listed(self) -> None:
        inventory = build_inventory(tunnels_for(PAIRS))
        assert len(inventory) == 5
        assert inventory.undocumented == []

    def test_the_status_is_unknown_rather_than_documented(self) -> None:
        """A report must not claim clearance it never checked for."""
        inventory = build_inventory(tunnels_for(PAIRS))
        assert all(e.status is InventoryStatus.UNKNOWN for e in inventory.entries)
        assert inventory.documented_list_supplied is False

    def test_no_unobserved_tunnels_are_invented(self) -> None:
        assert build_inventory(tunnels_for(PAIRS)).unobserved == []


class TestEndpointNormalisation:
    def test_ipv6_is_canonicalised(self) -> None:
        inventory = build_inventory(tunnels_for([("2001:0DB8:0000::0002", "2001:db8::1")]))
        assert inventory.entries[0].endpoints == ("2001:db8::1", "2001:db8::2")

    def test_an_ipv6_documented_list_matches_a_different_spelling(self) -> None:
        inventory = build_inventory(
            tunnels_for([("2001:db8::1", "2001:db8::2")]),
            known=known_from_endpoints(
                [("2001:0DB8:0000:0000:0000:0000:0000:0002", "2001:DB8::1")]
            ),
        )
        assert inventory.undocumented == [], "one address, three spellings, one tunnel"

    def test_ordering_is_numeric_within_a_family(self) -> None:
        """As strings, 192.0.2.10 sorts before 192.0.2.9 and the table looks broken."""
        inventory = build_inventory(tunnels_for([("192.0.2.10", "192.0.2.9")]))
        assert inventory.entries[0].endpoints == ("192.0.2.9", "192.0.2.10")

    def test_ordering_is_stable_regardless_of_observed_direction(self) -> None:
        forward = build_inventory(tunnels_for([("192.0.2.1", "192.0.2.2")]))
        backward = build_inventory(tunnels_for([("192.0.2.2", "192.0.2.1")]))
        assert forward.entries[0].endpoints == backward.entries[0].endpoints


class TestTunnelDetail:
    def test_the_negotiated_suite_is_summarised(self) -> None:
        entry = build_inventory(tunnels_for(PAIRS[:1])).entries[0]
        assert entry.negotiated_suite == "ENCR_AES_CBC-256 / 2048-bit MODP"

    def test_the_ike_version_is_carried(self) -> None:
        assert build_inventory(tunnels_for(PAIRS[:1])).entries[0].ike_version == "IKEv2"

    def test_aggressive_mode_is_surfaced_on_the_entry(self) -> None:
        """The inventory is often the only page an operator reads."""
        tunnels = correlate([exchange("192.0.2.1", "192.0.2.2", aggressive=True)], [])
        assert build_inventory(tunnels).entries[0].is_aggressive is True

    def test_an_orphan_is_listed_and_marked(self) -> None:
        tunnels = correlate([], [flow("192.0.2.1", "192.0.2.2")])
        entry = build_inventory(tunnels).entries[0]
        assert entry.orphan is True
        assert entry.ike_version is None
        assert entry.packet_count == 10

    def test_a_negotiation_with_no_traffic_is_listed_and_marked(self) -> None:
        tunnels = correlate([exchange("192.0.2.1", "192.0.2.2")], [])
        entry = build_inventory(tunnels).entries[0]
        assert entry.negotiation_only is True
        assert entry.packet_count == 0

    def test_an_orphan_has_no_suite_rather_than_a_guessed_one(self) -> None:
        tunnels = correlate([], [flow("192.0.2.1", "192.0.2.2")])
        assert build_inventory(tunnels).entries[0].negotiated_suite is None


CAPTURES = sorted(Path("data/raw/sweep").glob("*/capture_outer.pcap"))


@pytest.mark.skipif(len(CAPTURES) < 5, reason="no sweep captures present")
class TestAgainstRealCaptures:
    @staticmethod
    def _tunnels(pcap: Path) -> list[Tunnel]:
        return correlate(extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap)))

    def test_a_real_capture_inventories_to_one_tunnel(self) -> None:
        inventory = build_inventory(self._tunnels(CAPTURES[0]))
        assert len(inventory) == 1
        assert inventory.entries[0].packet_count > 0
        assert inventory.entries[0].negotiated_suite is not None

    def test_a_synthetic_undocumented_tunnel_is_flagged_against_real_ones(self) -> None:
        """M5's acceptance criterion, on real traffic plus one planted tunnel."""
        real = self._tunnels(CAPTURES[0])
        planted = correlate(
            [exchange("203.0.113.77", "203.0.113.88", offset_s=500)],
            [flow("203.0.113.77", "203.0.113.88", offset_s=501)],
        )
        known = known_from_endpoints([tuple(t.endpoints) for t in real])  # type: ignore[misc]
        inventory = build_inventory(real + planted, known=known)
        assert len(inventory.undocumented) == 1
        assert inventory.undocumented[0].endpoints == ("203.0.113.77", "203.0.113.88")

    def test_inventories_are_deterministic_across_runs(self) -> None:
        first = build_inventory(self._tunnels(CAPTURES[0]))
        second = build_inventory(self._tunnels(CAPTURES[0]))
        assert [e.tunnel_id for e in first.entries] == [e.tunnel_id for e in second.entries]


class TestSerialisation:
    def test_the_inventory_round_trips_through_json(self) -> None:
        """Reports and the API both serialise it; a field that cannot survive is a bug."""
        inventory = build_inventory(tunnels_for(PAIRS[:2]), known=known_from_endpoints(PAIRS[:1]))
        restored = Inventory.model_validate_json(inventory.model_dump_json())
        assert len(restored) == 2
        assert len(restored.undocumented) == 1

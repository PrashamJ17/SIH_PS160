"""Tests for ESP flow assembly (build plan Step 5.2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ipsec_sentinel.models import ESPFlow
from ipsec_sentinel.parser.esp import (
    ESPCaptureError,
    ESPPacket,
    assemble_esp_flows,
    extract_esp_packets,
    flows_from_capture,
)

BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)


def packet(
    spi: str = "deadbeef",
    sequence: int = 1,
    size: int = 100,
    src: str = "192.0.2.1",
    dst: str = "192.0.2.2",
    offset_s: float = 0.0,
) -> ESPPacket:
    return ESPPacket(
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=src,
        dst_ip=dst,
        spi=spi,
        sequence=sequence,
        size=size,
    )


class TestGrouping:
    def test_two_spis_produce_two_flows(self) -> None:
        flows = assemble_esp_flows([packet(spi="aaaaaaaa"), packet(spi="bbbbbbbb")])
        assert len(flows) == 2
        assert {f.spi for f in flows} == {"aaaaaaaa", "bbbbbbbb"}

    def test_bidirectional_traffic_produces_one_flow_per_direction(self) -> None:
        """An IPsec SA is unidirectional; a tunnel is two of them."""
        flows = assemble_esp_flows(
            [
                packet(spi="aaaaaaaa", src="192.0.2.1", dst="192.0.2.2"),
                packet(spi="bbbbbbbb", src="192.0.2.2", dst="192.0.2.1"),
            ]
        )
        assert len(flows) == 2
        assert {f.key for f in flows} == {
            ("192.0.2.1", "192.0.2.2", "aaaaaaaa"),
            ("192.0.2.2", "192.0.2.1", "bbbbbbbb"),
        }

    def test_the_two_directions_pair_on_a_normalised_endpoint_key(self) -> None:
        flows = assemble_esp_flows(
            [
                packet(spi="aaaaaaaa", src="192.0.2.1", dst="192.0.2.2"),
                packet(spi="bbbbbbbb", src="192.0.2.2", dst="192.0.2.1"),
            ]
        )
        assert flows[0].reverse_key == flows[1].reverse_key

    def test_the_same_spi_in_both_directions_stays_two_flows(self) -> None:
        """Rare but legal, and merging them would average away the asymmetry."""
        flows = assemble_esp_flows(
            [
                packet(spi="aaaaaaaa", src="192.0.2.1", dst="192.0.2.2"),
                packet(spi="aaaaaaaa", src="192.0.2.2", dst="192.0.2.1"),
            ]
        )
        assert len(flows) == 2

    def test_packets_of_one_flow_are_grouped_together(self) -> None:
        flows = assemble_esp_flows([packet(sequence=n) for n in range(1, 11)])
        assert len(flows) == 1
        assert flows[0].packet_count == 10

    def test_flows_come_back_in_first_seen_order(self) -> None:
        """Stable output across runs on the same capture."""
        flows = assemble_esp_flows(
            [packet(spi="cccccccc"), packet(spi="aaaaaaaa"), packet(spi="cccccccc")]
        )
        assert [f.spi for f in flows] == ["cccccccc", "aaaaaaaa"]


class TestAccounting:
    def test_byte_count_is_the_sum_of_packet_sizes(self) -> None:
        flows = assemble_esp_flows([packet(size=n) for n in (100, 250, 1400)])
        assert flows[0].byte_count == 1750
        assert flows[0].packet_count == 3

    def test_first_and_last_seen_span_the_flow(self) -> None:
        flows = assemble_esp_flows(
            [packet(offset_s=5.0), packet(offset_s=0.0), packet(offset_s=2.5)]
        )
        assert flows[0].first_seen == BASE
        assert flows[0].last_seen == BASE + timedelta(seconds=5)

    def test_the_per_packet_series_are_retained_for_feature_extraction(self) -> None:
        flows = assemble_esp_flows([packet(size=100, sequence=1), packet(size=200, sequence=2)])
        assert flows[0].sizes == [100, 200]
        assert flows[0].sequences == [1, 2]
        assert len(flows[0].timestamps) == 2

    def test_the_reporting_model_omits_the_per_packet_series(self) -> None:
        """A report needs counts and times, not a timing side channel of the traffic."""
        model = assemble_esp_flows([packet(size=100), packet(size=200)])[0].to_model()
        assert model.packet_count == 2
        assert model.byte_count == 300
        assert "sizes" not in ESPFlow.model_fields
        assert "timestamps" not in ESPFlow.model_fields

    def test_the_reporting_model_carries_the_addressing(self) -> None:
        model = assemble_esp_flows([packet()])[0].to_model()
        assert (model.src_ip, model.dst_ip, model.spi) == (
            "192.0.2.1",
            "192.0.2.2",
            "deadbeef",
        )


class TestEmpty:
    def test_empty_input_returns_an_empty_list(self) -> None:
        assert assemble_esp_flows([]) == []

    def test_a_generator_input_is_accepted(self) -> None:
        assert len(assemble_esp_flows(packet(sequence=n) for n in range(3))) == 1


class TestCaptureExtraction:
    def test_a_missing_capture_raises_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(ESPCaptureError):
            extract_esp_packets(tmp_path / "absent.pcap")

    def test_a_corrupt_capture_raises_a_clear_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"definitely not a capture")
        with pytest.raises(ESPCaptureError, match="not a pcap"):
            extract_esp_packets(bad)


@pytest.mark.skipif(
    not sorted(Path("data/raw/sweep").glob("*/capture_outer.pcap")),
    reason="no sweep captures present",
)
class TestAgainstRealCaptures:
    """The assembly has to survive real traffic, not only constructed packets."""

    @staticmethod
    def _first_capture() -> Path:
        return sorted(Path("data/raw/sweep").glob("*/capture_outer.pcap"))[0]

    def test_a_real_capture_yields_esp_flows(self) -> None:
        flows = flows_from_capture(self._first_capture())
        assert flows, "the sweep guarantees every cell carries ESP"

    def test_a_real_tunnel_shows_both_directions(self) -> None:
        """Two SAs, two SPIs, negotiated together — that is what a tunnel looks like."""
        flows = flows_from_capture(self._first_capture())
        directions = {(f.src_ip, f.dst_ip) for f in flows}
        assert len(directions) == 2, f"expected both directions, got {directions}"

    def test_real_flow_accounting_is_self_consistent(self) -> None:
        for flow in flows_from_capture(self._first_capture()):
            assert flow.packet_count == len(flow.sizes) == len(flow.timestamps)
            assert flow.byte_count == sum(flow.sizes)
            assert flow.first_seen <= flow.last_seen


class TestStructuralFloor:
    """IP protocol 50 is a claim, not a proof.

    This project's own replay generator emits protocol-50 packets from its source
    corpus onto the transit link. Counted as ESP they became hundreds of one-packet
    pseudo-flows with random SPIs, and inflated one traffic class from 36% to 61% of
    the ML dataset before the floor below was added.
    """

    @staticmethod
    def _esp_frame(body: bytes) -> bytes:
        import struct

        total = 20 + len(body)
        ipv4 = (
            struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 50, 0)
            + bytes((192, 0, 2, 1))
            + bytes((192, 0, 2, 2))
        )
        return b"\x02" * 6 + b"\x03" * 6 + struct.pack("!H", 0x0800) + ipv4 + body

    def test_a_packet_too_small_to_hold_an_icv_is_not_esp(self, tmp_path: Path) -> None:
        from ipsec_sentinel.parser.esp import MIN_AUTHENTICATED_ESP_BODY
        from tests.fixtures.builders import write_pcap

        body = b"\x00\x46\x4c\x77" + b"\xba\xaa\x30\xfd" + b"\xed\xff\xaa\xc0"
        assert len(body) < MIN_AUTHENTICATED_ESP_BODY
        pcap = write_pcap(tmp_path / "bogus.pcap", [self._esp_frame(body)])
        assert extract_esp_packets(pcap) == []

    def test_a_packet_large_enough_is_kept(self, tmp_path: Path) -> None:
        from ipsec_sentinel.parser.esp import MIN_AUTHENTICATED_ESP_BODY
        from tests.fixtures.builders import write_pcap

        body = b"\xaa" * MIN_AUTHENTICATED_ESP_BODY
        pcap = write_pcap(tmp_path / "real.pcap", [self._esp_frame(body)])
        assert len(extract_esp_packets(pcap)) == 1

    def test_the_floor_matches_the_rfc_arithmetic(self) -> None:
        """SPI 4 + Seq 4 + PadLength 1 + NextHeader 1 + the shortest common ICV, 12."""
        from ipsec_sentinel.parser.esp import MIN_AUTHENTICATED_ESP_BODY

        assert MIN_AUTHENTICATED_ESP_BODY == 4 + 4 + 1 + 1 + 12

    @pytest.mark.skipif(
        not sorted(Path("data/raw/sweep").glob("*replay*/capture_outer.pcap")),
        reason="no replay captures present",
    )
    def test_real_replay_captures_yield_only_the_two_real_flows(self) -> None:
        """A tunnel is two SAs. Anything more in these captures was an artefact."""
        for pcap in sorted(Path("data/raw/sweep").glob("*replay*/capture_outer.pcap"))[:6]:
            flows = flows_from_capture(pcap)
            assert len(flows) == 2, f"{pcap.parent.name} produced {len(flows)} flows"
            for flow in flows:
                assert flow.sequences[0] == 1, "a real SA starts its counter at 1"

"""Tests for capture ingestion (build plan Step 4.8).

The negative case carries the weight here. ESP-over-UDP on port 4500 handed to the IKE
parser yields a header read from ciphertext: an SPI, a version and an exchange type
made of random bytes. Some of those pass validation, and the result is a fabricated
negotiation reported as fact in the lane that carries no confidence score.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ipsec_sentinel.parser.pcap import (
    CaptureError,
    extract_ike_exchanges,
    is_ike_datagram,
    iter_ike_datagrams,
)
from tests.fixtures.builders import (
    IKE_PORT,
    NAT_T_PORT,
    build_esp_over_udp_frame,
    build_ikev1_aggressive,
    build_natt_ike_frame,
    build_strong_ike_sa_init,
    build_udp_frame,
    build_weak_ike_sa_init,
    write_pcap,
)


class TestPortFiveHundred:
    def test_the_expected_exchange_count_is_returned(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "ike.pcap",
            [
                build_udp_frame(build_strong_ike_sa_init()),
                build_udp_frame(build_weak_ike_sa_init()),
                build_udp_frame(build_strong_ike_sa_init()),
            ],
        )
        assert len(extract_ike_exchanges(pcap)) == 3

    def test_addressing_and_timestamps_are_carried_through(self, tmp_path: Path) -> None:
        """A finding that cannot say where and when it came from is an assertion."""
        pcap = write_pcap(
            tmp_path / "ike.pcap",
            [build_udp_frame(build_strong_ike_sa_init(), "198.51.100.7", "203.0.113.9")],
        )
        exchange = extract_ike_exchanges(pcap)[0]
        assert exchange.src_ip == "198.51.100.7"
        assert exchange.dst_ip == "203.0.113.9"
        assert exchange.timestamp.year >= 2023

    def test_the_proposals_survive_the_round_trip(self, tmp_path: Path) -> None:
        pcap = write_pcap(tmp_path / "weak.pcap", [build_udp_frame(build_weak_ike_sa_init())])
        names = {
            transform.name
            for exchange in extract_ike_exchanges(pcap)
            for proposal in exchange.proposals_offered
            for transform in proposal.transforms
        }
        assert "ENCR_3DES" in names

    def test_non_ike_udp_traffic_is_ignored(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "mixed.pcap",
            [
                build_udp_frame(b"\x00" * 64, src_port=53, dst_port=53),
                build_udp_frame(build_strong_ike_sa_init()),
            ],
        )
        assert len(extract_ike_exchanges(pcap)) == 1


class TestNATTraversal:
    def test_ike_behind_the_marker_parses(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "natt.pcap", [build_natt_ike_frame(build_strong_ike_sa_init())]
        )
        exchanges = extract_ike_exchanges(pcap)
        assert len(exchanges) == 1
        assert exchanges[0].exchange_type == "IKE_SA_INIT"

    def test_esp_over_udp_is_not_misparsed_as_ike(self, tmp_path: Path) -> None:
        """The bug this whole module is arranged around."""
        pcap = write_pcap(tmp_path / "esp.pcap", [build_esp_over_udp_frame()])
        assert extract_ike_exchanges(pcap) == []

    def test_a_mixed_4500_capture_keeps_only_the_ike(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "mixed4500.pcap",
            [
                build_esp_over_udp_frame(),
                build_natt_ike_frame(build_strong_ike_sa_init()),
                build_esp_over_udp_frame(spi=0x00ABCDEF),
            ],
        )
        assert len(extract_ike_exchanges(pcap)) == 1

    def test_the_marker_is_stripped_before_parsing(self, tmp_path: Path) -> None:
        """Leaving it on shifts every field four bytes and corrupts the SPI."""
        pcap = write_pcap(
            tmp_path / "natt.pcap", [build_natt_ike_frame(build_strong_ike_sa_init())]
        )
        assert extract_ike_exchanges(pcap)[0].initiator_spi == "11" * 8

    def test_the_datagram_is_marked_as_nat_traversed(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "natt.pcap", [build_natt_ike_frame(build_strong_ike_sa_init())]
        )
        assert next(iter_ike_datagrams(pcap)).nat_traversal is True


class TestMarkerClassification:
    def test_port_500_needs_no_marker(self) -> None:
        assert is_ike_datagram((IKE_PORT, 33000), b"\xff\xff\xff\xff") is True

    def test_port_4500_requires_the_marker(self) -> None:
        assert is_ike_datagram((NAT_T_PORT, NAT_T_PORT), b"\x00\x00\x00\x00abc") is True
        assert is_ike_datagram((NAT_T_PORT, NAT_T_PORT), b"\xde\xad\xbe\xef") is False

    def test_an_unrelated_port_pair_is_not_ike(self) -> None:
        assert is_ike_datagram((53, 33000), b"\x00\x00\x00\x00") is False

    def test_a_short_4500_payload_is_not_ike(self) -> None:
        assert is_ike_datagram((NAT_T_PORT, NAT_T_PORT), b"\x00\x00") is False


class TestIKEv1Ingestion:
    def test_an_ikev1_message_is_routed_to_the_v1_parser(self, tmp_path: Path) -> None:
        pcap = write_pcap(tmp_path / "v1.pcap", [build_udp_frame(build_ikev1_aggressive())])
        exchange = extract_ike_exchanges(pcap)[0]
        assert exchange.version == "IKEv1"
        assert exchange.is_aggressive is True

    def test_ikev1_attributes_are_projected_onto_the_shared_model(self, tmp_path: Path) -> None:
        pcap = write_pcap(tmp_path / "v1.pcap", [build_udp_frame(build_ikev1_aggressive())])
        names = {
            transform.name
            for proposal in extract_ike_exchanges(pcap)[0].proposals_offered
            for transform in proposal.transforms
        }
        assert "3DES_CBC" in names
        assert "MD5" in names

    def test_both_versions_in_one_capture_are_each_handled(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "both.pcap",
            [
                build_udp_frame(build_ikev1_aggressive()),
                build_udp_frame(build_strong_ike_sa_init()),
            ],
        )
        assert [e.version for e in extract_ike_exchanges(pcap)] == ["IKEv1", "IKEv2"]


class TestBadInput:
    def test_a_corrupt_file_raises_a_clear_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"this is not a capture file at all")
        with pytest.raises(CaptureError, match="not a pcap"):
            extract_ike_exchanges(bad)

    def test_a_missing_file_raises_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(CaptureError):
            extract_ike_exchanges(tmp_path / "absent.pcap")

    def test_pcapng_is_reported_rather_than_silently_empty(self, tmp_path: Path) -> None:
        ng = tmp_path / "x.pcapng"
        ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
        with pytest.raises(CaptureError, match="pcapng"):
            extract_ike_exchanges(ng)

    def test_an_empty_capture_returns_an_empty_list(self, tmp_path: Path) -> None:
        assert extract_ike_exchanges(write_pcap(tmp_path / "empty.pcap", [])) == []

    def test_a_capture_cut_mid_record_keeps_what_arrived(self, tmp_path: Path) -> None:
        """A capture killed mid-write is normal; the datagrams before the cut are good."""
        whole = write_pcap(
            tmp_path / "whole.pcap",
            [build_udp_frame(build_strong_ike_sa_init())] * 2,
        ).read_bytes()
        cut = tmp_path / "cut.pcap"
        cut.write_bytes(whole[: len(whole) - 30])
        assert len(extract_ike_exchanges(cut)) == 1

    def test_a_malformed_ike_message_does_not_discard_the_capture(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "mixed.pcap",
            [
                build_udp_frame(b"\xff" * 40),
                build_udp_frame(build_strong_ike_sa_init()),
            ],
        )
        assert len(extract_ike_exchanges(pcap)) >= 1

    def test_a_truncated_ike_message_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        pcap = write_pcap(tmp_path / "short.pcap", [build_udp_frame(b"\x11" * 12)])
        assert extract_ike_exchanges(pcap) == []


class TestTimestampResolution:
    def test_nanosecond_captures_are_read_at_the_right_scale(self, tmp_path: Path) -> None:
        """Reading nanoseconds as microseconds shifts every stamp by 1000x."""
        frames = [build_udp_frame(build_strong_ike_sa_init())]
        micro = extract_ike_exchanges(write_pcap(tmp_path / "us.pcap", frames))[0]
        nano = extract_ike_exchanges(write_pcap(tmp_path / "ns.pcap", frames, nanosecond=True))[0]
        assert micro.timestamp == nano.timestamp

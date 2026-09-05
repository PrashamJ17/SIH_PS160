"""Tests for the external dataset IPsec audit (build plan Step 3.5).

This step is one of the four the plan says cannot be cut, because the audit is the
project's strongest credibility artifact. An audit that miscounts — in either
direction — is worse than none, so the scanner is tested against captures whose
IPsec content is known exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from ipsec_sentinel.data.pcap_scan import find_captures, scan_capture

ETHER = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def esp_packet() -> object:
    """ESP is IP protocol 50; its payload is opaque."""
    return Ether(**ETHER) / IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / Raw(b"\x11" * 64)


def ah_packet() -> object:
    return Ether(**ETHER) / IP(src="10.0.0.1", dst="10.0.0.2", proto=51) / Raw(b"\x22" * 48)


def ike_500_packet() -> object:
    return (
        Ether(**ETHER)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=500, dport=500)
        / Raw(b"\xaa" * 8 + b"\x00" * 20)
    )


def ike_4500_packet() -> object:
    """On 4500 a four-zero-byte non-ESP marker precedes the IKE header."""
    return (
        Ether(**ETHER)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=4500, dport=4500)
        / Raw(b"\x00\x00\x00\x00" + b"\xbb" * 28)
    )


def esp_over_udp_packet() -> object:
    """Also on 4500, but with no marker — this is ESP, not IKE."""
    return (
        Ether(**ETHER)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=4500, dport=4500)
        / Raw(b"\xde\xad\xbe\xef" + b"\xcc" * 40)
    )


def benign_packets(count: int = 20) -> list[object]:
    """The kind of traffic the named corpora actually contain."""
    out: list[object] = []
    for index in range(count):
        if index % 4 == 0:
            out.append(Ether(**ETHER) / IP(src="192.168.1.5", dst="93.184.216.34") / ICMP())
        elif index % 4 == 1:
            out.append(
                Ether(**ETHER)
                / IP(src="192.168.1.5", dst="93.184.216.34")
                / UDP(sport=53, dport=53)
                / Raw(b"dns")
            )
        else:
            out.append(
                Ether(**ETHER)
                / IP(src="192.168.1.5", dst="93.184.216.34")
                / TCP(sport=44000 + index, dport=443)
                / Raw(b"x" * 100)
            )
    return out


@pytest.fixture
def ipsec_capture(tmp_path: Path) -> Path:
    path = tmp_path / "with_ipsec.pcap"
    packets = (
        [esp_packet() for _ in range(7)]
        + [ah_packet() for _ in range(3)]
        + [ike_500_packet() for _ in range(4)]
        + [ike_4500_packet() for _ in range(2)]
        + [esp_over_udp_packet() for _ in range(5)]
        + benign_packets(10)
    )
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def benign_capture(tmp_path: Path) -> Path:
    path = tmp_path / "no_ipsec.pcap"
    wrpcap(str(path), benign_packets(40))
    return path


class TestKnownIPsecContent:
    def test_esp_packets_are_counted(self, ipsec_capture: Path) -> None:
        assert scan_capture(ipsec_capture).esp_packets == 7

    def test_ah_packets_are_counted(self, ipsec_capture: Path) -> None:
        assert scan_capture(ipsec_capture).ah_packets == 3

    def test_ike_on_port_500_is_counted(self, ipsec_capture: Path) -> None:
        assert scan_capture(ipsec_capture).ike_udp500_packets == 4

    def test_ike_on_port_4500_with_the_marker_is_counted(self, ipsec_capture: Path) -> None:
        assert scan_capture(ipsec_capture).ike_udp4500_packets == 2

    def test_esp_over_udp_is_not_counted_as_ike(self, ipsec_capture: Path) -> None:
        """Counting it as IKE would overstate the finding on any NAT-T capture."""
        result = scan_capture(ipsec_capture)
        assert result.esp_over_udp_packets == 5
        assert result.ike_packets == 6

    def test_totals_add_up(self, ipsec_capture: Path) -> None:
        result = scan_capture(ipsec_capture)
        assert result.total_packets == 31
        assert result.ipsec_packets == 16
        assert result.has_ipsec is True


class TestNoIPsecContent:
    def test_every_ipsec_counter_is_zero(self, benign_capture: Path) -> None:
        result = scan_capture(benign_capture)
        assert result.esp_packets == 0
        assert result.ah_packets == 0
        assert result.ike_packets == 0
        assert result.esp_over_udp_packets == 0

    def test_it_still_sees_the_packets(self, benign_capture: Path) -> None:
        """Zero IPsec must not be confused with zero packets read."""
        result = scan_capture(benign_capture)
        assert result.total_packets == 40
        assert result.ipv4_packets == 40
        assert result.has_ipsec is False

    def test_ordinary_udp_is_not_mistaken_for_ike(self, tmp_path: Path) -> None:
        path = tmp_path / "dns.pcap"
        wrpcap(
            str(path),
            [
                Ether(**ETHER)
                / IP(src="1.1.1.1", dst="2.2.2.2")
                / UDP(sport=5000, dport=50000)
                / Raw(b"x" * 32)
                for _ in range(10)
            ],
        )
        assert scan_capture(path).ike_packets == 0


class TestRobustness:
    def test_a_missing_file_is_reported_not_raised(self, tmp_path: Path) -> None:
        result = scan_capture(tmp_path / "absent.pcap")
        assert result.readable is False
        assert result.error

    def test_a_non_pcap_file_is_reported_not_raised(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("this is not a capture")
        result = scan_capture(path)
        assert result.readable is False
        assert "not a pcap" in (result.error or "")

    def test_an_empty_file_is_reported_not_raised(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.pcap"
        path.write_bytes(b"")
        assert scan_capture(path).readable is False

    def test_a_truncated_capture_counts_what_it_can(
        self, ipsec_capture: Path, tmp_path: Path
    ) -> None:
        """An audit that dies on one corrupt file cannot survey a corpus."""
        data = ipsec_capture.read_bytes()
        cut = tmp_path / "truncated.pcap"
        cut.write_bytes(data[: len(data) // 2])
        result = scan_capture(cut)
        assert result.readable is True
        assert 0 < result.total_packets < 31

    def test_a_corrupt_length_field_does_not_hang(self, tmp_path: Path) -> None:
        import struct

        path = tmp_path / "corrupt.pcap"
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        # A record claiming a preposterous length must terminate the walk.
        record = struct.pack("<IIII", 0, 0, 0xFFFFFFF, 0xFFFFFFF)
        path.write_bytes(header + record + b"\x00" * 32)
        assert scan_capture(path).total_packets == 0

    def test_max_packets_caps_the_walk(self, ipsec_capture: Path) -> None:
        result = scan_capture(ipsec_capture, max_packets=5)
        assert result.truncated is True
        assert result.notes


class TestDiscovery:
    def test_captures_are_found_recursively(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        wrpcap(str(nested / "one.pcap"), benign_packets(2))
        wrpcap(str(tmp_path / "two.pcap"), benign_packets(2))
        assert len(find_captures(tmp_path)) == 2

    def test_a_missing_directory_yields_nothing(self, tmp_path: Path) -> None:
        assert find_captures(tmp_path / "absent") == []

    def test_non_captures_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "readme.md").write_text("not a capture")
        wrpcap(str(tmp_path / "real.pcap"), benign_packets(2))
        assert len(find_captures(tmp_path)) == 1


class TestAuditScript:
    """The audit's own guard rails (build plan Step 3.5)."""

    def test_control_requires_both_ike_and_esp(self) -> None:
        """ESP alone is not enough: a scanner blind to IKE would still report zero."""
        from ipsec_sentinel.data.pcap_scan import ScanResult
        from scripts.audit_external_datasets import control_is_valid

        esp_only = ScanResult(path="a", esp_packets=10)
        ike_only = ScanResult(path="b", ike_udp500_packets=4)
        assert control_is_valid([esp_only]) is False
        assert control_is_valid([ike_only]) is False
        assert control_is_valid([esp_only, ike_only]) is True

    def test_an_empty_control_is_invalid(self) -> None:
        from scripts.audit_external_datasets import control_is_valid

        assert control_is_valid([]) is False

    def test_a_failed_control_marks_the_report_invalid(self) -> None:
        """A zero from an unproven counter must never be presented as a finding."""
        from ipsec_sentinel.data.pcap_scan import ScanResult
        from scripts.audit_external_datasets import render_report

        report = render_report([], [ScanResult(path="x")], control_ok=False)
        assert "INVALID" in report
        assert "must not be cited" in report

    def test_a_passing_control_marks_the_report_valid(self) -> None:
        from ipsec_sentinel.data.pcap_scan import ScanResult
        from scripts.audit_external_datasets import render_report

        report = render_report(
            [], [ScanResult(path="x", esp_packets=1, ike_udp500_packets=1)], control_ok=True
        )
        assert "Control result: PASS" in report

    def test_a_failed_control_exits_non_zero(self, tmp_path: Path) -> None:
        from scripts.audit_external_datasets import main

        code = main(
            [
                "--external",
                str(tmp_path / "none"),
                "--control",
                str(tmp_path / "empty"),
                "--report",
                str(tmp_path / "report.md"),
                "--json",
                str(tmp_path / "report.json"),
            ]
        )
        assert code == 1

    def test_report_names_every_dataset_the_problem_statement_lists(self) -> None:
        from scripts.audit_external_datasets import NAMED_DATASETS

        for key in (
            "cicids2017",
            "csecicids2018",
            "unswnb15",
            "ctu13",
            "ciciot2023",
            "lanl",
            "darpa",
        ):
            assert key in NAMED_DATASETS

    def test_a_scanned_corpus_with_ipsec_is_reported_as_such(
        self, ipsec_capture: Path, tmp_path: Path
    ) -> None:
        """The audit must be able to report a non-zero, or its zero means nothing."""
        from scripts.audit_external_datasets import audit_directory

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "sample.pcap").write_bytes(ipsec_capture.read_bytes())
        audit = audit_directory("fake", "a corpus that does contain IPsec", corpus)
        assert audit.present is True
        assert audit.ipsec_packets == 16

    def test_a_scanned_corpus_without_ipsec_reports_zero(
        self, benign_capture: Path, tmp_path: Path
    ) -> None:
        from scripts.audit_external_datasets import audit_directory

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "sample.pcap").write_bytes(benign_capture.read_bytes())
        audit = audit_directory("fake", "a corpus with no IPsec", corpus)
        assert audit.present is True
        assert audit.total_packets == 40
        assert audit.ipsec_packets == 0

    def test_an_absent_corpus_is_reported_as_absent_not_as_zero(self, tmp_path: Path) -> None:
        """Reporting only what was measured; an absent corpus is not evidence."""
        from scripts.audit_external_datasets import audit_directory

        audit = audit_directory("missing", "not downloaded", tmp_path / "nothing")
        assert audit.present is False
        assert audit.files_scanned == 0

"""Tests for corpus validation and packaging (build plan Step 3.6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from scripts.package_dataset import (
    PackagingError,
    build_index,
    check_balance,
    find_manifests,
    package,
    validate_cell,
)

ETHER = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def write_capture(path: Path, count: int = 8) -> None:
    wrpcap(
        str(path),
        [
            Ether(**ETHER)
            / IP(src="10.1.0.10", dst="10.2.0.10")
            / UDP(sport=1000 + i, dport=2000)
            / Raw(b"x" * 64)
            for i in range(count)
        ],
    )


def make_cell(
    root: Path,
    cell_id: str,
    *,
    generator: str = "icmp",
    variant: str = "steady_1s",
    impairment: str = "clean",
    encryption: str = "AES_CBC",
    dh_group: str = "MODP_1024",
    matched: bool = True,
    write_outer: bool = True,
    write_inner: bool = True,
) -> Path:
    cell = root / cell_id
    cell.mkdir(parents=True, exist_ok=True)
    if write_outer:
        write_capture(cell / "capture_outer.pcap", 12)
    if write_inner:
        write_capture(cell / "capture_inner.pcap", 20)
    manifest = {
        "capture_id": cell_id,
        "config_id": cell_id.split("_")[0],
        "intent": {"encryption": "aes128", "dh_group": "modp1024", "mode": "tunnel", "pfs": True},
        "negotiated_ike": {
            "established": True,
            "ike_version": "IKEv2",
            "encryption": encryption,
            "encryption_keylen": 128,
            "integrity": None,
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": dh_group,
            "initiator_spi": "aa",
            "responder_spi": "bb",
            "local_host": "10.100.0.2",
            "remote_host": "10.100.0.3",
            "local_port": 500,
            "remote_port": 500,
            "nat_t": False,
        },
        "negotiated_child": {
            "installed": True,
            "mode": "tunnel",
            "esp_encryption": encryption,
            "esp_keylen": 128,
            "esp_integrity": None,
            "spi_in": "1234abcd",
            "spi_out": "5678efab",
            "local_ts": "10.1.0.0/24",
            "remote_ts": "10.2.0.0/24",
            "reqid": 1,
        },
        "kernel_sas": [],
        "negotiation_matched_intent": matched,
        "mismatches": [] if matched else ["encryption: intended X, negotiated Y"],
        "capture_meta": {
            "generator": generator,
            "variant": variant,
            "impairment": impairment,
            "outer_pcap": "capture_outer.pcap",
            "inner_pcap": "capture_inner.pcap",
        },
    }
    (cell / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return cell


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "sweep"
    for index, (generator, encryption) in enumerate(
        [("icmp", "AES_CBC"), ("icmp", "AES_GCM_16"), ("voip", "AES_CBC"), ("voip", "AES_GCM_16")]
    ):
        make_cell(
            root, f"cfg{index}_{generator}_v_clean_r0", generator=generator, encryption=encryption
        )
    return root


class TestDiscoveryAndValidation:
    def test_manifests_are_found(self, corpus: Path) -> None:
        assert len(find_manifests(corpus)) == 4

    def test_a_valid_cell_validates(self, corpus: Path) -> None:
        record = validate_cell(find_manifests(corpus)[0])
        assert record.files["outer_pcap"]["packets"] == 12
        assert record.files["inner_pcap"]["packets"] == 20
        assert len(record.files["outer_pcap"]["sha256"]) == 64

    def test_a_missing_pcap_fails_with_the_file_named(self, tmp_path: Path) -> None:
        """ "Packaging failed" without a path is useless across a thousand cells."""
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0", write_outer=False)
        with pytest.raises(PackagingError, match="does not exist"):
            validate_cell(cell / "manifest.json")

    def test_a_schema_invalid_manifest_fails(self, tmp_path: Path) -> None:
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0")
        (cell / "manifest.json").write_text(json.dumps({"capture_id": "only-this"}))
        with pytest.raises(PackagingError, match="does not validate against the schema"):
            validate_cell(cell / "manifest.json")

    def test_unparseable_json_fails(self, tmp_path: Path) -> None:
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0")
        (cell / "manifest.json").write_text("{ not json")
        with pytest.raises(PackagingError, match="does not validate"):
            validate_cell(cell / "manifest.json")

    def test_an_unreadable_pcap_fails(self, tmp_path: Path) -> None:
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0")
        (cell / "capture_outer.pcap").write_bytes(b"not a capture at all")
        with pytest.raises(PackagingError, match="unusable"):
            validate_cell(cell / "manifest.json")

    def test_a_truncated_pcap_fails(self, tmp_path: Path) -> None:
        """An index must never promise data that will not read back."""
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0")
        capture = cell / "capture_inner.pcap"
        data = capture.read_bytes()
        capture.write_bytes(data[: len(data) - 30])
        with pytest.raises(PackagingError, match="unusable"):
            validate_cell(cell / "manifest.json")

    def test_a_manifest_without_a_capture_reference_fails(self, tmp_path: Path) -> None:
        cell = make_cell(tmp_path / "s", "cfg_x_v_clean_r0")
        manifest = json.loads((cell / "manifest.json").read_text())
        del manifest["capture_meta"]["outer_pcap"]
        (cell / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(PackagingError, match="records no outer_pcap"):
            validate_cell(cell / "manifest.json")


class TestIndex:
    def test_counts_match_the_file_inventory(self, corpus: Path) -> None:
        index = build_index([validate_cell(m) for m in find_manifests(corpus)], corpus)
        assert index["cells"] == 4
        assert sum(index["counts"]["per_class"].values()) == 4
        assert index["counts"]["per_class"] == {"icmp": 2, "voip": 2}

    def test_packet_totals_match_the_captures(self, corpus: Path) -> None:
        index = build_index([validate_cell(m) for m in find_manifests(corpus)], corpus)
        assert index["totals"]["outer_packets"] == 4 * 12
        assert index["totals"]["inner_packets"] == 4 * 20

    def test_cells_not_matching_intent_are_counted_separately(self, tmp_path: Path) -> None:
        """A cell whose negotiation diverged must be visible, not blended in."""
        root = tmp_path / "s"
        make_cell(root, "a_icmp_v_clean_r0", matched=True)
        make_cell(root, "b_icmp_v_clean_r0", matched=False)
        index = build_index([validate_cell(m) for m in find_manifests(root)], root)
        assert index["cells_matching_intent"] == 1
        assert index["cells_not_matching_intent"] == 1

    def test_index_records_a_checksum_per_file(self, corpus: Path) -> None:
        index = build_index([validate_cell(m) for m in find_manifests(corpus)], corpus)
        for cell in index["cells_detail"]:
            for role in ("outer_pcap", "inner_pcap", "manifest"):
                assert len(cell["files"][role]["sha256"]) == 64


class TestBalanceReporting:
    def test_a_balanced_corpus_produces_no_warning(self, corpus: Path) -> None:
        index = build_index([validate_cell(m) for m in find_manifests(corpus)], corpus)
        assert check_balance(index) == []

    def test_a_confounded_corpus_is_reported_not_hidden(self, tmp_path: Path) -> None:
        """A model trained on a confounded corpus scores well on the wrong signal."""
        root = tmp_path / "s"
        make_cell(root, "a_voip_v_clean_r0", generator="voip", encryption="AES_GCM_16")
        make_cell(root, "b_video_v_clean_r0", generator="video", encryption="AES_CBC")
        index = build_index([validate_cell(m) for m in find_manifests(root)], root)
        warnings = check_balance(index)
        assert warnings
        assert any("voip" in w for w in warnings)
        assert any("cipher rather than shape" in w for w in warnings)


class TestPackaging:
    def test_package_writes_index_and_datacard(self, corpus: Path, tmp_path: Path) -> None:
        out = tmp_path / "dataset"
        package(corpus, out)
        assert (out / "INDEX.json").exists()
        assert (out / "DATACARD.md").exists()

    def test_datacard_states_what_the_corpus_is_not_fit_for(
        self, corpus: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "dataset"
        package(corpus, out)
        card = (out / "DATACARD.md").read_text()
        assert "What it is not fit for" in card
        assert "not WhatsApp" in card or "it is not WhatsApp" in card
        assert "strongSwan on both ends" in card

    def test_datacard_reports_a_confound_when_present(self, tmp_path: Path) -> None:
        root = tmp_path / "s"
        make_cell(root, "a_voip_v_clean_r0", generator="voip", encryption="AES_GCM_16")
        make_cell(root, "b_video_v_clean_r0", generator="video", encryption="AES_CBC")
        out = tmp_path / "dataset"
        package(root, out)
        assert "This corpus is confounded" in (out / "DATACARD.md").read_text()

    def test_an_empty_source_fails_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(PackagingError, match="no manifests found"):
            package(tmp_path / "nothing", tmp_path / "out")

    def test_packaging_fails_rather_than_indexing_missing_data(self, tmp_path: Path) -> None:
        root = tmp_path / "s"
        make_cell(root, "a_icmp_v_clean_r0")
        make_cell(root, "b_icmp_v_clean_r0", write_inner=False)
        with pytest.raises(PackagingError, match="does not exist"):
            package(root, tmp_path / "out")
        assert not (tmp_path / "out" / "INDEX.json").exists()

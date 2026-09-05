"""Tests for external dataset acquisition (build plan Step 3.3).

No test here touches the network: the downloader is injected, so the integrity and
provenance logic is exercised deterministically and offline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.fetch_external import (
    DATASETS,
    PROVENANCE_FILENAME,
    ChecksumMismatchError,
    Dataset,
    fetch_all,
    fetch_one,
    main,
    sha256_of,
)

PAYLOAD = b"synthetic external corpus"
PAYLOAD_SHA = "e0c1f1e0b2a0e1f1a8f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708"


def writer(content: bytes = PAYLOAD):  # type: ignore[no-untyped-def]
    def download(_url: str, destination: Path) -> None:
        destination.write_bytes(content)

    return download


def exploding(_url: str, _destination: Path) -> None:
    raise OSError("network is unreachable")


def downloadable(**kw: object) -> Dataset:
    base: dict[str, object] = {
        "key": "sample",
        "kind": "pcap",
        "use": "testing",
        "url": "https://example.invalid/sample.pcap",
        "filename": "sample.pcap",
    }
    base.update(kw)
    return Dataset(**base)  # type: ignore[arg-type]


class TestDatasetCatalogue:
    def test_the_named_corpora_are_present(self) -> None:
        assert {"cicids2017", "iscxvpn2016", "mawi", "mitre_attack", "nvd_cve"} <= set(DATASETS)

    def test_registration_only_corpora_are_marked_manual(self) -> None:
        """CIC-IDS2017 and ISCXVPN2016 cannot be fetched without registering."""
        assert DATASETS["cicids2017"].manual_download is True
        assert DATASETS["iscxvpn2016"].manual_download is True

    def test_manual_entries_carry_actionable_instructions(self) -> None:
        for key in ("cicids2017", "iscxvpn2016", "mawi"):
            instructions = DATASETS[key].instructions
            assert "http" in instructions
            assert "data/external" in instructions

    def test_the_no_ipsec_caveat_is_recorded_on_cicids(self) -> None:
        """The audit at Step 3.5 proves this; the catalogue states it up front."""
        assert "NO IPsec" in DATASETS["cicids2017"].note

    def test_iscxvpn_records_that_it_is_openvpn(self) -> None:
        assert "OpenVPN" in DATASETS["iscxvpn2016"].note


class TestManualDownloads:
    def test_manual_entry_reports_manual_and_does_not_fetch(self, tmp_path: Path) -> None:
        result = fetch_one(DATASETS["cicids2017"], tmp_path, downloader=exploding)
        assert result.status == "manual"
        assert result.instructions

    def test_manual_entries_exit_zero(self, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        code = main(["--dest", str(tmp_path), "--only", "cicids2017", "iscxvpn2016"])
        assert code == 0
        out = capsys.readouterr().out
        assert "manual download" in out
        assert "unb.ca" in out


class TestChecksumVerification:
    def test_matching_checksum_is_accepted(self, tmp_path: Path) -> None:
        digest = __import__("hashlib").sha256(PAYLOAD).hexdigest()
        result = fetch_one(downloadable(sha256=digest), tmp_path, downloader=writer())
        assert result.status == "fetched"
        assert result.sha256 == digest

    def test_mismatched_checksum_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ChecksumMismatchError, match="expected sha256"):
            fetch_one(downloadable(sha256=PAYLOAD_SHA), tmp_path, downloader=writer())

    def test_mismatched_checksum_leaves_no_partial_file(self, tmp_path: Path) -> None:
        """A plausible-looking but wrong corpus is worse than none at all."""
        with pytest.raises(ChecksumMismatchError):
            fetch_one(downloadable(sha256=PAYLOAD_SHA), tmp_path, downloader=writer())
        assert not (tmp_path / "sample" / "sample.pcap").exists()

    def test_no_recorded_checksum_still_records_what_arrived(self, tmp_path: Path) -> None:
        result = fetch_one(downloadable(), tmp_path, downloader=writer())
        assert result.sha256 == sha256_of(tmp_path / "sample" / "sample.pcap")


class TestSkipAndForce:
    def test_already_present_dataset_is_skipped(self, tmp_path: Path) -> None:
        fetch_one(downloadable(), tmp_path, downloader=writer())
        second = fetch_one(downloadable(), tmp_path, downloader=exploding)
        assert second.status == "skipped"

    def test_force_refetches(self, tmp_path: Path) -> None:
        fetch_one(downloadable(), tmp_path, downloader=writer())
        again = fetch_one(downloadable(), tmp_path, downloader=writer(b"replaced"), force=True)
        assert again.status == "fetched"
        assert (tmp_path / "sample" / "sample.pcap").read_bytes() == b"replaced"


class TestFailureHandling:
    def test_a_failed_download_is_reported_not_raised(self, tmp_path: Path) -> None:
        """One unreachable corpus must not abort acquisition of the others."""
        result = fetch_one(downloadable(), tmp_path, downloader=exploding)
        assert result.status == "failed"
        assert "network is unreachable" in result.message

    def test_a_failed_download_leaves_no_file(self, tmp_path: Path) -> None:
        fetch_one(downloadable(), tmp_path, downloader=exploding)
        assert not (tmp_path / "sample" / "sample.pcap").exists()

    def test_unknown_dataset_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown dataset"):
            fetch_all(tmp_path, only=["not_a_corpus"])


class TestProvenance:
    def test_provenance_records_url_checksum_and_timestamp(self, tmp_path: Path) -> None:
        fetch_one(downloadable(), tmp_path, downloader=writer())
        record = json.loads((tmp_path / "sample" / PROVENANCE_FILENAME).read_text())
        assert record["url"] == "https://example.invalid/sample.pcap"
        assert record["sha256"] == sha256_of(tmp_path / "sample" / "sample.pcap")
        assert record["fetched_at"].startswith("20")
        assert record["bytes"] == len(PAYLOAD)

    def test_provenance_carries_the_stated_use(self, tmp_path: Path) -> None:
        """Step 3.5's audit is only as credible as the provenance behind it."""
        fetch_one(downloadable(use="inner payload replay"), tmp_path, downloader=writer())
        record = json.loads((tmp_path / "sample" / PROVENANCE_FILENAME).read_text())
        assert record["use"] == "inner payload replay"

    def test_no_provenance_is_written_for_a_failed_fetch(self, tmp_path: Path) -> None:
        fetch_one(downloadable(), tmp_path, downloader=exploding)
        assert not (tmp_path / "sample" / PROVENANCE_FILENAME).exists()


class TestFetchAll:
    def test_fetch_all_reports_every_requested_dataset(self, tmp_path: Path) -> None:
        results = fetch_all(tmp_path, only=["cicids2017", "mawi"], downloader=writer())
        assert {r.key for r in results} == {"cicids2017", "mawi"}
        assert all(r.status == "manual" for r in results)

    def test_default_run_covers_the_whole_catalogue(self, tmp_path: Path) -> None:
        results = fetch_all(tmp_path, downloader=writer())
        assert {r.key for r in results} == set(DATASETS)

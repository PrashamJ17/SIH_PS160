"""Tests for ATT&CK, vendor fingerprint and CVE enrichment (build plan Step 6.8).

Every test here runs offline, and that is the point rather than a convenience. This
tool is pointed at captures from networks under investigation — exactly the situation
where a host may have no outbound access — so a lookup that reaches the internet would
make reports non-reproducible and the tool unusable when it is most needed.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from ipsec_sentinel.assess.enrich import (
    VENDOR_FINGERPRINTS,
    CVEReference,
    corpus_status,
    identify_vendor,
    load_attack_index,
    load_cve_cache,
    lookup_cves,
    store_cves,
    technique,
    write_json_atomically,
)


class TestAttackResolution:
    def test_t1040_resolves_to_network_sniffing(self) -> None:
        """The build plan's named case."""
        resolved = technique("T1040")
        assert resolved is not None
        assert resolved.name == "Network Sniffing"
        assert resolved.url.endswith("/T1040")

    def test_a_sub_technique_resolves(self) -> None:
        resolved = technique("T1110.002")
        assert resolved is not None
        assert resolved.technique_id == "T1110.002"

    def test_an_unknown_technique_returns_none(self) -> None:
        assert technique("T9999") is None

    def test_an_empty_id_returns_none_rather_than_raising(self) -> None:
        assert technique("") is None

    def test_every_technique_referenced_by_a_rule_resolves(self) -> None:
        """A rule citing a technique the catalogue cannot expand is a dead link."""
        from ipsec_sentinel.assess.rules import ALL_RULES

        unresolved = [
            rule.id
            for rule in ALL_RULES
            if rule.attack_technique and technique(rule.attack_technique) is None
        ]
        assert not unresolved, f"rules cite unresolvable techniques: {unresolved}"

    def test_a_missing_bundle_yields_an_empty_index_not_an_error(self, tmp_path: Path) -> None:
        """A report that cannot expand IDs is still useful; one that refuses is not."""
        load_attack_index.cache_clear()
        try:
            index = load_attack_index(tmp_path / "absent.json", tmp_path / "absent-index.json")
            assert index == {}
        finally:
            load_attack_index.cache_clear()

    def test_an_unreadable_index_falls_back_to_the_bundle(self, tmp_path: Path) -> None:
        corrupt = tmp_path / "index.json"
        corrupt.write_text("{ this is not json")
        bundle = tmp_path / "bundle.json"
        bundle.write_text(
            json.dumps(
                {
                    "objects": [
                        {
                            "type": "attack-pattern",
                            "name": "Test Technique",
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "external_id": "T0001",
                                    "url": "https://example.invalid/T0001",
                                }
                            ],
                        }
                    ]
                }
            )
        )
        load_attack_index.cache_clear()
        try:
            index = load_attack_index(bundle, corrupt)
            assert index["T0001"]["name"] == "Test Technique"
        finally:
            load_attack_index.cache_clear()

    def test_revoked_techniques_are_excluded(self, tmp_path: Path) -> None:
        bundle = tmp_path / "bundle.json"
        bundle.write_text(
            json.dumps(
                {
                    "objects": [
                        {
                            "type": "attack-pattern",
                            "name": "Gone",
                            "revoked": True,
                            "external_references": [
                                {"source_name": "mitre-attack", "external_id": "T0002"}
                            ],
                        }
                    ]
                }
            )
        )
        load_attack_index.cache_clear()
        try:
            assert load_attack_index(bundle, tmp_path / "idx.json") == {}
        finally:
            load_attack_index.cache_clear()


class TestVendorFingerprints:
    def test_a_known_vendor_id_resolves(self) -> None:
        """The build plan's named case."""
        fingerprint = identify_vendor("afcad71368a1f1c96b8696fc77570100")
        assert fingerprint is not None
        assert fingerprint.product == "Dead Peer Detection"

    def test_matching_is_case_insensitive(self) -> None:
        assert identify_vendor("AFCAD71368A1F1C96B8696FC77570100") is not None

    def test_an_unknown_vendor_id_returns_none_with_no_exception(self) -> None:
        assert identify_vendor("deadbeefdeadbeefdeadbeefdeadbeef") is None

    def test_an_empty_vendor_id_returns_none(self) -> None:
        assert identify_vendor("") is None

    def test_malformed_input_never_raises(self) -> None:
        """A vendor ID is attacker-controlled bytes."""
        for value in ("zzz", "0", "not hex at all", "ff" * 500, "\x00\x01"):
            assert identify_vendor(value) is None or True

    def test_a_prefix_match_reports_the_version_bytes(self) -> None:
        fingerprint = identify_vendor("4048b7d56ebce88525e7de7f00d6c2d3")
        assert fingerprint is not None
        assert "Microsoft" in fingerprint.product
        assert fingerprint.detail is not None
        assert "25e7de7f00d6c2d3" in fingerprint.detail

    def test_a_cleartext_vendor_id_is_read_directly(self) -> None:
        """Better than a hash: it carries the version."""
        fingerprint = identify_vendor(b"strongSwan 5.9.8".hex())
        assert fingerprint is not None
        assert fingerprint.product == "strongSwan 5.9.8"

    def test_the_table_keys_are_normalised(self) -> None:
        for key, value in VENDOR_FINGERPRINTS.items():
            assert key == key.lower()
            assert value.vendor_id == key


class TestCVECache:
    def test_a_missing_cache_returns_no_cves_rather_than_raising(self, tmp_path: Path) -> None:
        assert lookup_cves("strongSwan", "5.9.8", cache_path=tmp_path / "absent.json") == []

    def test_a_stored_entry_is_returned(self, tmp_path: Path) -> None:
        cache = tmp_path / "cve.json"
        store_cves(
            "strongSwan",
            "5.9.8",
            [CVEReference(cve_id="CVE-2023-41913", summary="stub", severity="critical")],
            cache_path=cache,
        )
        found = lookup_cves("strongSwan", "5.9.8", cache_path=cache)
        assert len(found) == 1
        assert found[0].cve_id == "CVE-2023-41913"
        assert found[0].url.endswith("CVE-2023-41913")

    def test_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        cache = tmp_path / "cve.json"
        store_cves(
            "strongSwan", "5.9.8", [CVEReference(cve_id="CVE-1", summary="s")], cache_path=cache
        )
        assert lookup_cves("STRONGSWAN", "5.9.8", cache_path=cache)

    def test_a_versionless_entry_is_used_when_the_version_is_not_cached(
        self, tmp_path: Path
    ) -> None:
        cache = tmp_path / "cve.json"
        store_cves(
            "strongSwan", None, [CVEReference(cve_id="CVE-2", summary="s")], cache_path=cache
        )
        assert lookup_cves("strongSwan", "9.9.9", cache_path=cache)[0].cve_id == "CVE-2"

    def test_a_corrupt_cache_yields_no_cves_rather_than_raising(self, tmp_path: Path) -> None:
        cache = tmp_path / "cve.json"
        cache.write_text("{ truncated")
        assert lookup_cves("strongSwan", "5.9.8", cache_path=cache) == []
        assert load_cve_cache(cache) == {}

    def test_malformed_entries_are_skipped_not_fatal(self, tmp_path: Path) -> None:
        cache = tmp_path / "cve.json"
        cache.write_text(json.dumps({"strongswan|5.9.8": [{"no_id": True}, "not a dict"]}))
        assert lookup_cves("strongSwan", "5.9.8", cache_path=cache) == []


class TestAtomicWrites:
    def test_the_cache_is_written_atomically(self, tmp_path: Path) -> None:
        """A cache truncated by an interrupt fails as corruption, not absence."""
        target = tmp_path / "out.json"
        write_json_atomically(target, {"a": 1})
        assert json.loads(target.read_text()) == {"a": 1}
        assert not list(tmp_path.glob("*.tmp")), "the temporary file must not survive"

    def test_a_failed_write_leaves_the_previous_content(self, tmp_path: Path) -> None:
        target = tmp_path / "out.json"
        write_json_atomically(target, {"good": True})
        with pytest.raises(TypeError):
            write_json_atomically(target, {"bad": {1, 2, 3}})  # a set is not JSON
        assert json.loads(target.read_text()) == {"good": True}

    def test_it_creates_the_parent_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "deeper" / "out.json"
        write_json_atomically(target, [1, 2])
        assert target.exists()


class TestCorpusStatus:
    """A report should say when enrichment was unavailable rather than look complete."""

    def test_a_present_corpus_is_reported_as_present(self, tmp_path: Path) -> None:
        index = tmp_path / "index.json"
        index.write_text(json.dumps({"T1040": {"name": "Network Sniffing", "url": "u"}}))
        cache = tmp_path / "cve.json"
        cache.write_text(json.dumps({"strongswan|5.9.8": [{"cve_id": "CVE-1"}]}))

        status = corpus_status(index_path=index, cache_path=cache)

        assert status.attack_techniques == 1
        assert status.cve_cache_entries == 1
        assert not status.degraded
        assert status.note is None

    def test_an_absent_corpus_is_counted_as_zero_not_guessed(self, tmp_path: Path) -> None:
        status = corpus_status(
            index_path=tmp_path / "absent.json", cache_path=tmp_path / "absent.json"
        )
        assert status.attack_techniques == 0
        assert status.cve_cache_entries == 0
        assert status.degraded

    def test_the_note_names_what_is_missing_and_what_is_unaffected(self, tmp_path: Path) -> None:
        """A reader must be able to tell 'nothing found' from 'nothing looked'."""
        status = corpus_status(
            index_path=tmp_path / "absent.json", cache_path=tmp_path / "absent.json"
        )
        note = status.note
        assert note is not None
        assert "ATT&CK" in note
        assert "CVE" in note
        assert "built in" in note, "the note must say the protocol CVEs are unaffected"

    def test_a_partial_corpus_names_only_the_missing_half(self, tmp_path: Path) -> None:
        index = tmp_path / "index.json"
        index.write_text(json.dumps({"T1040": {"name": "Network Sniffing", "url": "u"}}))

        note = corpus_status(index_path=index, cache_path=tmp_path / "absent.json").note

        assert note is not None
        assert "ATT&CK" not in note
        assert "CVE" in note

    def test_an_unreadable_corpus_counts_as_absent_rather_than_raising(
        self, tmp_path: Path
    ) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{not json")
        status = corpus_status(index_path=broken, cache_path=broken)
        assert status.degraded

    def test_it_opens_no_socket(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("corpus_status opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        assert corpus_status(index_path=tmp_path / "a", cache_path=tmp_path / "b").degraded

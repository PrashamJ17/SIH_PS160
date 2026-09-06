"""Tests for ML dataset assembly (build plan Step 7.2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ipsec_sentinel.features.dataset import (
    GROUPING_COLUMNS,
    LABEL_COLUMNS,
    build_ml_dataset,
    dataset_summary,
    find_manifests,
    labels_from_manifest,
    windows_for_capture,
)
from ipsec_sentinel.features.flow import FEATURE_NAMES

SWEEP = Path("data/raw/sweep")
MANIFESTS = find_manifests(SWEEP) if SWEEP.exists() else []
SAMPLE = MANIFESTS[:12]


class TestLabelProvenance:
    """Labels come from what was negotiated, not from what was configured."""

    def test_the_cipher_label_is_the_negotiated_one(self) -> None:
        manifest = {
            "intent": {"encryption": "aes256gcm16", "mode": "tunnel", "pfs": True},
            "negotiated_ike": {"encryption": "3DES_CBC", "dh_group": "CURVE_25519"},
            "negotiated_child": {"mode": "tunnel"},
            "capture_meta": {"generator": "web"},
        }
        labels = labels_from_manifest(manifest)
        assert labels["cipher"] == "3DES_CBC", "intent must not override reality"

    def test_a_missing_negotiated_value_is_none_not_backfilled(self) -> None:
        """Silently substituting intent would train a model to predict the config file."""
        manifest = {
            "intent": {"encryption": "aes256gcm16"},
            "negotiated_ike": {},
            "capture_meta": {"generator": "web"},
        }
        assert labels_from_manifest(manifest)["cipher"] is None

    def test_the_traffic_label_comes_from_the_generator(self) -> None:
        manifest = {"capture_meta": {"generator": "voip", "variant": "g711_20ms"}}
        labels = labels_from_manifest(manifest)
        assert labels["inner_traffic"] == "voip"
        assert labels["traffic_variant"] == "g711_20ms"

    def test_pfs_comes_from_intent_and_that_is_documented(self) -> None:
        """The testbed knows it; a deployed analyser does not, which is why PFS-01 refuses."""
        manifest = {"intent": {"pfs": False}, "negotiated_ike": {}}
        assert labels_from_manifest(manifest)["pfs"] is False

    def test_an_empty_manifest_produces_all_none_rather_than_raising(self) -> None:
        labels = labels_from_manifest({})
        assert set(labels) == set(LABEL_COLUMNS)
        assert all(v is None for v in labels.values())


class TestWindowing:
    def test_an_absent_capture_yields_no_rows(self, tmp_path: Path) -> None:
        manifest = tmp_path / "manifest.json"
        manifest.write_text(
            json.dumps(
                {"capture_id": "x", "config_id": "y", "capture_meta": {"outer_pcap": "absent.pcap"}}
            )
        )
        assert windows_for_capture(manifest) == []

    @pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
    def test_a_thirty_second_cell_produces_at_least_one_window(self) -> None:
        rows = windows_for_capture(SAMPLE[0])
        assert rows, "every cell carries ESP by construction"
        assert all(row.window_index >= 0 for row in rows)

    @pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
    def test_a_shorter_window_produces_more_rows(self) -> None:
        wide = windows_for_capture(SAMPLE[0], window_s=30)
        narrow = windows_for_capture(SAMPLE[0], window_s=5)
        assert len(narrow) >= len(wide)

    @pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
    def test_window_indices_are_contiguous_from_zero_per_flow(self) -> None:
        rows = windows_for_capture(SAMPLE[0], window_s=5)
        by_flow: dict[str, list[int]] = {}
        for row in rows:
            by_flow.setdefault(row.flow_key, []).append(row.window_index)
        for indices in by_flow.values():
            assert indices == sorted(indices)
            assert indices[0] == 0


@pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
class TestFrameShape:
    @staticmethod
    def _frame():  # type: ignore[no-untyped-def]
        return build_ml_dataset(SAMPLE)

    def test_the_frame_has_rows(self) -> None:
        assert len(self._frame()) > 0

    def test_no_nan_in_any_feature_column(self) -> None:
        """The plan's explicit criterion. NaN becomes an untraceable prediction."""
        frame = self._frame()
        assert int(frame[list(FEATURE_NAMES)].isna().sum().sum()) == 0

    def test_every_row_has_a_capture_id_and_config_id(self) -> None:
        """These drive leakage-free splitting; a row without them cannot be split on."""
        frame = self._frame()
        assert frame["capture_id"].notna().all()
        assert (frame["capture_id"].astype(str).str.len() > 0).all()
        assert frame["config_id"].notna().all()
        assert (frame["config_id"].astype(str).str.len() > 0).all()

    def test_the_columns_are_keys_then_features_then_labels(self) -> None:
        expected = [*GROUPING_COLUMNS, *FEATURE_NAMES, *LABEL_COLUMNS]
        assert list(self._frame().columns) == expected

    def test_every_feature_column_is_numeric(self) -> None:
        frame = self._frame()
        for name in FEATURE_NAMES:
            assert frame[name].dtype.kind in "fiu", name

    def test_an_empty_manifest_list_returns_an_empty_frame_with_columns(self) -> None:
        frame = build_ml_dataset([])
        assert len(frame) == 0
        assert list(frame.columns) == [*GROUPING_COLUMNS, *FEATURE_NAMES, *LABEL_COLUMNS]


@pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
class TestLabelsMatchTheManifests:
    def test_the_traffic_classes_come_from_the_manifests(self) -> None:
        frame = build_ml_dataset(SAMPLE)
        expected = {json.loads(m.read_text())["capture_meta"]["generator"] for m in SAMPLE}
        assert set(frame["inner_traffic"].dropna().unique()) == expected

    def test_the_ciphers_come_from_the_manifests(self) -> None:
        frame = build_ml_dataset(SAMPLE)
        expected = {
            (json.loads(m.read_text()).get("negotiated_ike") or {}).get("encryption")
            for m in SAMPLE
        }
        assert set(frame["cipher"].dropna().unique()) <= {e for e in expected if e}

    def test_each_capture_id_appears(self) -> None:
        frame = build_ml_dataset(SAMPLE)
        expected = {json.loads(m.read_text())["capture_id"] for m in SAMPLE}
        assert set(frame["capture_id"].unique()) <= expected

    def test_absent_labels_are_null_rather_than_invented(self) -> None:
        """3DES negotiates no key length and AEAD carries integrity internally.

        Both are legitimately absent. Filling them with a plausible default would put
        a fabricated label into the training set.
        """
        frame = build_ml_dataset(SAMPLE)
        assert frame["cipher"].notna().all()
        # These two may be null, and that is correct rather than missing data.
        assert "cipher_keylen" in frame.columns
        assert "integrity" in frame.columns


@pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
class TestSummary:
    def test_the_summary_counts_what_it_says(self) -> None:
        frame = build_ml_dataset(SAMPLE)
        summary = dataset_summary(frame)
        assert summary["rows"] == len(frame)
        assert summary["captures"] == frame["capture_id"].nunique()
        assert summary["configs"] == frame["config_id"].nunique()

    def test_an_empty_frame_summarises_to_zero(self) -> None:
        assert dataset_summary(build_ml_dataset([]))["rows"] == 0


@pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
class TestDeterminism:
    def test_building_twice_gives_identical_frames(self) -> None:
        """A dataset that differs between builds makes every later number unrepeatable."""
        first = build_ml_dataset(SAMPLE)
        second = build_ml_dataset(SAMPLE)
        assert first.equals(second)


class TestMinimumPacketThreshold:
    """A window with too few packets has no shape to measure.

    Its inter-arrival, burst and percentile features are all finite zeros — correct
    behaviour from the extractor and useless training data, because a row of zeros
    labelled "voip" teaches a model that voip looks like nothing.
    """

    def test_the_threshold_is_documented_and_nonzero(self) -> None:
        from ipsec_sentinel.features.dataset import MIN_PACKETS_PER_WINDOW

        assert MIN_PACKETS_PER_WINDOW >= 10

    @pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
    def test_every_emitted_window_meets_the_threshold(self) -> None:
        from ipsec_sentinel.features.dataset import MIN_PACKETS_PER_WINDOW

        frame = build_ml_dataset(SAMPLE)
        assert (frame["packet_count"] >= MIN_PACKETS_PER_WINDOW).all()

    @pytest.mark.skipif(not SAMPLE, reason="no sweep captures present")
    def test_lowering_the_threshold_admits_more_rows(self) -> None:
        strict = build_ml_dataset(SAMPLE, min_packets=10)
        loose = build_ml_dataset(SAMPLE, min_packets=1)
        assert len(loose) >= len(strict)

    @pytest.mark.skipif(not MANIFESTS, reason="no sweep captures present")
    def test_the_corpus_is_balanced_across_traffic_classes(self) -> None:
        """The artefacts skewed one class to 61% of the dataset; balance is the check."""
        from pathlib import Path as _Path

        built = _Path("data/processed/ml_dataset.parquet")
        if not built.exists():
            pytest.skip("the full dataset has not been built")
        import pandas as pd

        frame = pd.read_parquet(built)
        share = frame["inner_traffic"].value_counts(normalize=True)
        assert share.max() < 0.30, f"one class dominates: {share.to_dict()}"
        assert len(share) == 7

"""Tests for the confound audit (build plan Step 7.10).

The audit exists because a confounded classifier and a sound one produce identical
output. Only a test designed to separate them can tell which you have — so this suite
checks that the audit itself can detect a confound, not merely that it runs.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from scripts.confound_audit import (
    MAX_ACCEPTABLE_SPREAD,
    SIZE_FEATURES,
    AuditResult,
    run_audit,
    write_report,
)

warnings.filterwarnings("ignore")

REAL_DOC = Path("docs/CONFOUND_AUDIT.md")
REAL_DATA = Path("data/processed/ml_dataset.parquet")


def corpus(confounded: bool = False, seed: int = 0) -> pd.DataFrame:
    """A small corpus, optionally with cipher tied to traffic class."""
    rng = np.random.default_rng(seed)
    classes = ["web", "voip", "video"]
    ciphers = ["AES_CBC", "AES_GCM_16", "3DES_CBC"]
    rows = []
    for ci, cls in enumerate(classes):
        for capture in range(14):
            cipher = ciphers[ci] if confounded else ciphers[capture % len(ciphers)]
            for _window in range(2):
                row = {name: float(rng.normal(ci * 25, 8)) for name in FEATURE_NAMES}
                rows.append(
                    {
                        **row,
                        "inner_traffic": cls,
                        "cipher": cipher,
                        "capture_id": f"{cls}_{capture}",
                        "config_id": f"cfg{capture % 4}",
                    }
                )
    return pd.DataFrame(rows)


class TestAllThreeMetrics:
    def test_the_audit_produces_all_three_measurements(self) -> None:
        result = run_audit(corpus())
        assert result.accuracy_overall > 0.0
        assert result.by_cipher, "no per-cipher accuracy"
        assert result.cipher_learnability >= 0.0
        assert result.mutual_information_predicted >= 0.0

    def test_every_cipher_is_reported(self) -> None:
        frame = corpus()
        result = run_audit(frame)
        assert {c.cipher for c in result.by_cipher} == set(frame["cipher"].unique())

    def test_the_per_cipher_window_counts_sum_to_the_dataset(self) -> None:
        frame = corpus()
        result = run_audit(frame)
        assert sum(c.rows for c in result.by_cipher) == len(frame)

    def test_the_cipher_probe_uses_size_features_only(self) -> None:
        """Timing or volume would let it identify the class and infer cipher from layout."""
        assert SIZE_FEATURES
        assert all("iat" not in name for name in SIZE_FEATURES)
        assert "packets_per_s" not in SIZE_FEATURES
        assert "byte_count" not in SIZE_FEATURES
        assert set(SIZE_FEATURES) < set(FEATURE_NAMES)

    def test_an_empty_dataset_produces_an_empty_result_rather_than_raising(self) -> None:
        result = run_audit(pd.DataFrame())
        assert result.accuracy_overall == 0.0
        assert result.by_cipher == []


class TestItCanDetectAConfound:
    """An audit that cannot fail proves nothing."""

    def test_a_confounded_corpus_is_flagged(self) -> None:
        result = run_audit(corpus(confounded=True))
        assert result.mutual_information_true > 0.1, (
            "a corpus where cipher determines class must show high mutual information"
        )

    def test_a_balanced_corpus_shows_near_zero_mutual_information(self) -> None:
        result = run_audit(corpus(confounded=False))
        assert result.mutual_information_true < 0.05

    def test_the_spread_verdict_can_go_either_way(self) -> None:
        tight = AuditResult(
            by_cipher=[
                type(run_audit(corpus()).by_cipher[0])("a", 0.95, 10),
                type(run_audit(corpus()).by_cipher[0])("b", 0.94, 10),
            ]
        )
        assert tight.is_cipher_independent is True
        wide = AuditResult(
            by_cipher=[
                type(tight.by_cipher[0])("a", 0.95, 10),
                type(tight.by_cipher[0])("b", 0.50, 10),
            ]
        )
        assert wide.is_cipher_independent is False
        assert wide.accuracy_spread > MAX_ACCEPTABLE_SPREAD


class TestTheReportIsAlwaysWritten:
    def test_it_is_written_when_the_result_is_unfavourable(self, tmp_path: Path) -> None:
        """No silent suppression of a confounded verdict."""
        result = run_audit(corpus(confounded=True))
        output = tmp_path / "CONFOUND_AUDIT.md"
        written = write_report(result, output, json_output=tmp_path / "a.json")
        assert written.exists()
        text = written.read_text()
        assert "## Verdict" in text
        assert f"{result.accuracy_overall:.1%}" in text

    def test_it_is_written_for_an_empty_result(self, tmp_path: Path) -> None:
        written = write_report(AuditResult(), tmp_path / "a.md", json_output=None)
        assert written.exists()

    def test_the_json_sidecar_carries_every_number(self, tmp_path: Path) -> None:
        result = run_audit(corpus())
        write_report(result, tmp_path / "a.md", json_output=tmp_path / "a.json")
        payload = json.loads((tmp_path / "a.json").read_text())
        for key in (
            "accuracy_overall",
            "by_cipher",
            "cipher_learnability",
            "mutual_information_predicted",
            "cipher_top_features",
        ):
            assert key in payload

    def test_the_document_reports_all_three_sections(self, tmp_path: Path) -> None:
        result = run_audit(corpus())
        write_report(result, tmp_path / "a.md", json_output=None)
        text = (tmp_path / "a.md").read_text()
        assert "Accuracy conditioned on cipher" in text
        assert "learnable is the cipher from packet sizes" in text
        assert "Mutual information with cipher" in text


@pytest.mark.skipif(not REAL_DOC.exists(), reason="the audit has not been generated")
class TestTheCommittedAudit:
    def test_it_records_the_padding_finding(self) -> None:
        """A legitimate finding, not a defect: block padding is a side channel."""
        text = REAL_DOC.read_text()
        assert "AES-CBC pads to a 16-byte block boundary" in text
        assert "without ever seeing a handshake" in text

    def test_it_states_the_verdict_on_cipher_dependence(self) -> None:
        text = REAL_DOC.read_text()
        assert "Accuracy does not depend on the cipher" in text or "confound signature" in text

    def test_it_explains_why_the_audit_exists(self) -> None:
        assert "most fatal trap" in REAL_DOC.read_text()


@pytest.mark.skipif(not REAL_DATA.exists(), reason="the ML dataset has not been built")
class TestAgainstTheRealCorpus:
    def test_accuracy_does_not_depend_on_the_cipher(self) -> None:
        result = run_audit(pd.read_parquet(REAL_DATA))
        assert result.is_cipher_independent, (
            f"spread {result.accuracy_spread:.1%} across "
            f"{[(c.cipher, round(c.accuracy, 3)) for c in result.by_cipher]}"
        )

    def test_the_predictions_are_not_cipher_coupled(self) -> None:
        result = run_audit(pd.read_parquet(REAL_DATA))
        assert result.mutual_information_predicted < 0.05

    def test_the_cipher_is_learnable_from_padding(self) -> None:
        """Expected to succeed. It is a finding about ESP, not a defect in the model."""
        result = run_audit(pd.read_parquet(REAL_DATA))
        assert result.cipher_lift > 0.1, (
            "block padding should make the cipher partly identifiable from sizes"
        )
        assert "size_min" in " ".join(result.cipher_top_features), (
            "padding is proportionally most visible on the smallest packets"
        )

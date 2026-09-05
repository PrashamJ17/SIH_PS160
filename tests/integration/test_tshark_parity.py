"""Independent confirmation of the parser against Wireshark (build plan Step 4.10).

Every other test in the parser suite checks this parser against fixtures this project
wrote. That proves internal consistency and says nothing about whether the RFCs were
read correctly — a misreading would be baked into the fixture and the test alike.
tshark is an independent implementation maintained for decades by people who have seen
far more real IKE than this project will, so where the two disagree the burden of proof
is here.

The suite includes a negative control. A parity check that cannot detect a mismatch
proves nothing, and one comparing two empty lists passes loudly while testing nothing
at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.compare_with_tshark import (
    MessageSummary,
    compare,
    sentinel_summary,
    tshark_available,
    tshark_summary,
)
from tests.fixtures.builders import (
    build_ikev1_aggressive,
    build_multi_proposal_ike_sa_init,
    build_strong_ike_sa_init,
    build_udp_frame,
    build_weak_ike_sa_init,
    write_pcap,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not tshark_available(), reason="tshark is not installed"),
]

SWEEP_ROOT = Path("data/raw/sweep")


def dataset_captures() -> list[Path]:
    if not SWEEP_ROOT.exists():
        return []
    return sorted(SWEEP_ROOT.glob("*/capture_outer.pcap"))


class TestSyntheticParity:
    """Fixtures first: a failure here localises the bug far faster than a sweep does."""

    @pytest.mark.parametrize(
        "build",
        [
            build_strong_ike_sa_init,
            build_weak_ike_sa_init,
            build_multi_proposal_ike_sa_init,
            build_ikev1_aggressive,
        ],
        ids=["strong", "weak", "multi_proposal", "ikev1_aggressive"],
    )
    def test_each_fixture_agrees_with_tshark(self, build, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        pcap = write_pcap(tmp_path / "fixture.pcap", [build_udp_frame(build())])
        result = compare(pcap)
        assert result.agrees, "\n" + "\n".join(str(d) for d in result.discrepancies)
        assert result.tshark_messages, "the check must not pass by comparing nothing"

    def test_a_multi_message_capture_agrees_message_by_message(self, tmp_path: Path) -> None:
        pcap = write_pcap(
            tmp_path / "many.pcap",
            [
                build_udp_frame(build_strong_ike_sa_init()),
                build_udp_frame(build_weak_ike_sa_init()),
                build_udp_frame(build_ikev1_aggressive()),
                build_udp_frame(build_multi_proposal_ike_sa_init()),
            ],
        )
        result = compare(pcap)
        assert result.agrees, "\n" + "\n".join(str(d) for d in result.discrepancies)
        assert len(result.tshark_messages) == 4


class TestNegativeControl:
    """Prove the comparator can fail. Without this the whole step is decorative."""

    def test_a_transform_mismatch_is_detected(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        pcap = write_pcap(tmp_path / "fixture.pcap", [build_udp_frame(build_strong_ike_sa_init())])
        truth = sentinel_summary(pcap)[0]
        wrong = MessageSummary(
            version_major=truth.version_major,
            exchange_type=truth.exchange_type,
            transforms=((1, 3),),  # claim 3DES where the capture offers AES-GCM
            key_lengths=truth.key_lengths,
        )
        monkeypatch.setattr("scripts.compare_with_tshark.sentinel_summary", lambda _p: [wrong])
        result = compare(pcap)
        assert not result.agrees
        assert any(d.field_name == "transforms" for d in result.discrepancies)

    def test_a_version_mismatch_is_detected(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        pcap = write_pcap(tmp_path / "fixture.pcap", [build_udp_frame(build_strong_ike_sa_init())])
        truth = sentinel_summary(pcap)[0]
        monkeypatch.setattr(
            "scripts.compare_with_tshark.sentinel_summary",
            lambda _p: [
                MessageSummary(
                    version_major=1,
                    exchange_type=truth.exchange_type,
                    transforms=truth.transforms,
                    key_lengths=truth.key_lengths,
                )
            ],
        )
        assert not compare(pcap).agrees

    def test_a_missed_message_is_detected(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Silently dropping a message is the failure mode a summary comparison hides."""
        pcap = write_pcap(
            tmp_path / "fixture.pcap",
            [build_udp_frame(build_strong_ike_sa_init())] * 3,
        )
        monkeypatch.setattr("scripts.compare_with_tshark.sentinel_summary", lambda _p: [])
        result = compare(pcap)
        assert not result.agrees
        assert any(d.field_name == "message count" for d in result.discrepancies)


@pytest.mark.skipif(not dataset_captures(), reason="no sweep captures present")
class TestDatasetParity:
    """The real evidence: captures produced by strongSwan, not by this project."""

    def test_every_dataset_capture_agrees_with_tshark(self) -> None:
        captures = dataset_captures()
        failures: list[str] = []
        compared = 0
        for pcap in captures:
            result = compare(pcap)
            compared += len(result.tshark_messages)
            if not result.agrees:
                failures.append(f"{pcap}\n" + "\n".join(str(d) for d in result.discrepancies))
        assert not failures, "\n\n".join(failures)
        assert compared > 0, "the parity check must compare real messages, not zero"

    def test_the_dataset_actually_contains_ike(self) -> None:
        """Guards the guard: a sweep of empty captures would pass parity vacuously."""
        total = sum(len(tshark_summary(pcap)) for pcap in dataset_captures()[:10])
        assert total > 0, "tshark found no ISAKMP in the dataset at all"

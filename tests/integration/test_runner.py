"""One sweep cell, end to end (build plan Step 3.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from testbed.orchestrate.matrix import expand_matrix
from testbed.orchestrate.netem import profile
from testbed.orchestrate.runner import CellSpec, run_cell
from tests.fixtures.dockerctl import docker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]


def anchor(label: str):  # type: ignore[no-untyped-def]
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def sentinel_containers() -> list[str]:
    return [
        n
        for n in docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
        if n.startswith("sentinel-cell-")
    ]


@pytest.fixture(scope="module")
def happy_cell(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    out = tmp_path_factory.mktemp("cell_ok")
    cell = CellSpec(anchor("weak"), generator="icmp", variant="steady_1s", impairment="clean")
    outcome = run_cell(cell, profile("clean"), duration_s=8, out_dir=out)
    return outcome, out


def test_happy_path_succeeds(happy_cell) -> None:  # type: ignore[no-untyped-def]
    outcome, _ = happy_cell
    assert outcome.success is True, outcome.error


def test_happy_path_produces_both_pcaps_and_a_manifest(happy_cell) -> None:  # type: ignore[no-untyped-def]
    outcome, out = happy_cell
    assert Path(outcome.outer_pcap).exists()
    assert Path(outcome.inner_pcap).exists()
    assert (out / "manifest.json").exists()
    assert outcome.outer_packets > 0
    assert outcome.inner_packets > 0


def test_manifest_records_the_negotiation_and_the_cell(happy_cell) -> None:  # type: ignore[no-untyped-def]
    outcome, out = happy_cell
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["negotiation_matched_intent"] is True, manifest["mismatches"]
    assert outcome.negotiation_matched_intent is True
    assert manifest["capture_meta"]["generator"] == "icmp"
    assert manifest["capture_meta"]["impairment"] == "clean"


def test_manifest_records_the_impairment_applied(happy_cell) -> None:  # type: ignore[no-untyped-def]
    _, out = happy_cell
    netem = json.loads((out / "manifest.json").read_text())["capture_meta"]["netem"]
    assert netem == {"delay_ms": 0, "jitter_ms": 0, "loss_pct": 0.0, "rate_mbit": None}


def test_cell_id_is_stable_and_descriptive() -> None:
    cell = CellSpec(
        anchor("weak"), generator="voip", variant="g711_20ms", impairment="wan_poor", repeat=2
    )
    assert (
        cell.cell_id
        == CellSpec(
            anchor("weak"), generator="voip", variant="g711_20ms", impairment="wan_poor", repeat=2
        ).cell_id
    )
    assert "voip" in cell.cell_id and "wan_poor" in cell.cell_id and cell.cell_id.endswith("_r2")


def test_an_impaired_cell_still_completes(tmp_path: Path) -> None:
    """Impairment is applied for real, and the cell survives it."""
    cell = CellSpec(anchor("good"), generator="icmp", variant="steady_1s", impairment="wan_good")
    outcome = run_cell(cell, profile("wan_good"), duration_s=8, out_dir=tmp_path)
    assert outcome.success is True, outcome.error
    netem = json.loads((tmp_path / "manifest.json").read_text())["capture_meta"]["netem"]
    assert netem["delay_ms"] == 20


def test_an_unbuildable_generator_is_a_recorded_failure(tmp_path: Path) -> None:
    """A cell that cannot run must not raise; the sweep has to continue."""
    cell = CellSpec(
        anchor("weak"), generator="replay", variant="cicids2017_benign", impairment="clean"
    )
    outcome = run_cell(cell, profile("clean"), duration_s=5, out_dir=tmp_path)
    assert outcome.success is False
    assert outcome.error is not None
    assert "replay source" in outcome.error or "requires a replay source" in outcome.error


def test_a_failed_cell_leaves_no_containers(tmp_path: Path) -> None:
    """Teardown runs in a finally block; a leak would poison every later cell."""
    before = set(sentinel_containers())
    cell = CellSpec(anchor("weak"), generator="replay", variant="mawi_sample", impairment="clean")
    run_cell(cell, profile("clean"), duration_s=5, out_dir=tmp_path)
    assert set(sentinel_containers()) - before == set()


def test_a_failed_cell_leaves_no_networks(tmp_path: Path) -> None:
    before = {
        n
        for n in docker("network", "ls", "--format", "{{.Name}}").stdout.split()
        if n.startswith("sentinel-cell-")
    }
    cell = CellSpec(anchor("weak"), generator="replay", variant="mawi_sample", impairment="clean")
    run_cell(cell, profile("clean"), duration_s=5, out_dir=tmp_path)
    after = {
        n
        for n in docker("network", "ls", "--format", "{{.Name}}").stdout.split()
        if n.startswith("sentinel-cell-")
    }
    assert after - before == set()


def test_outer_capture_contains_the_handshake(happy_cell) -> None:  # type: ignore[no-untyped-def]
    """Capture must start before initiation or the parser lane has nothing to read."""
    from scapy.all import UDP, PcapReader

    outcome, _ = happy_cell
    with PcapReader(outcome.outer_pcap) as reader:
        ike = [
            p
            for p in reader
            if p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500))
        ]
    assert len(ike) >= 2, "no IKE in the outer capture — capture started too late"

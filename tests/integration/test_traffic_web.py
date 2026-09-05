"""Web browsing generator over a live tunnel (build plan Step 2.5)."""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from scapy.all import IP, TCP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.web import VARIANTS, WEB_ORIGIN_IP, WebGenerator

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
DURATION_S = 45


@pytest.fixture(scope="module")
def web_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, list[int]]:
    out = tmp_path_factory.mktemp("web")
    with running_pair(out, profiles=("web",)) as ctx:
        gen = WebGenerator("skimming", seed=11)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        gen.teardown()
        return outcome, capture.inner_pcap, list(gen.pages_visited)


@pytest.fixture(scope="module")
def rotation(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[int], list[int]]:
    """Two runs with different seeds, to prove the page set rotates."""
    out = tmp_path_factory.mktemp("web_rotation")
    visited: list[list[int]] = []
    with running_pair(out, profiles=("web",)) as ctx:
        for seed in (1, 2):
            gen = WebGenerator("skimming", seed=seed)
            gen.setup(ctx)
            gen.run(12)
            visited.append(list(gen.pages_visited))
            gen.teardown()
    return visited[0], visited[1]


def web_packets(path: Path) -> list:  # type: ignore[type-arg]
    with PcapReader(str(path)) as reader:
        return [
            p
            for p in reader
            if p.haslayer(TCP) and p.haslayer(IP) and WEB_ORIGIN_IP in (p[IP].src, p[IP].dst)
        ]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(WebGenerator(), TrafficGenerator)


def test_generator_declares_the_origin_it_requires() -> None:
    assert "web" in WebGenerator().requires


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown web variant"):
        WebGenerator("doomscrolling")


def test_run_reports_success(web_run: tuple[object, Path, list[int]]) -> None:
    outcome, _, _ = web_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]


def test_request_response_asymmetry(web_run: tuple[object, Path, list[int]]) -> None:
    """Small requests out, large responses in — the defining browsing asymmetry."""
    _, inner, _ = web_run
    packets = web_packets(inner)
    down = sum(len(p) for p in packets if p[IP].src == WEB_ORIGIN_IP)
    up = sum(len(p) for p in packets if p[IP].dst == WEB_ORIGIN_IP)
    assert up > 0 and down > 0
    assert down / up >= 3.0, f"downstream/upstream only {down / up:.1f} — not asymmetric"


def test_at_least_two_think_time_gaps_over_two_seconds(
    web_run: tuple[object, Path, list[int]],
) -> None:
    """The reader pauses. A steady stream would be a download, not browsing."""
    _, inner, _ = web_run
    times = sorted(float(p.time) for p in web_packets(inner))
    assert len(times) > 30
    gaps = [b - a for a, b in itertools.pairwise(times)]
    long_gaps = [g for g in gaps if g > 2.0]
    assert len(long_gaps) >= 2, f"expected at least 2 think-time gaps over 2s, saw {len(long_gaps)}"


def test_more_than_one_page_is_visited(web_run: tuple[object, Path, list[int]]) -> None:
    _, _, visited = web_run
    assert len(visited) >= 2


def test_consecutive_runs_fetch_different_page_sets(
    rotation: tuple[list[int], list[int]],
) -> None:
    """Fetching an identical corpus every run would let the model memorise content."""
    first, second = rotation
    assert first and second
    assert set(first) ^ set(second), (
        f"both runs fetched the same pages ({sorted(set(first))}) — no rotation"
    )


def test_variants_differ_in_think_time() -> None:
    assert len({(v.think_min_s, v.think_max_s) for v in VARIANTS.values()}) == 2

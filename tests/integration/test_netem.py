"""Impairment profiles applied to a live pair (build plan Step 2.9)."""

from __future__ import annotations

import re

import pytest

from testbed.orchestrate.capture import interface_holding
from testbed.orchestrate.netem import active_qdisc, apply_profile, clear, impaired, profile
from tests.fixtures.dockerctl import exec_in

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
RIGHT_TRANSIT = "10.100.0.3"


def measure_rtt_ms(container: str, target: str, count: int = 6) -> float:
    """Average round-trip time, measured with ping."""
    result = exec_in(container, "ping", "-c", str(count), "-W", "5", target, timeout=90)
    match = re.search(r"=\s*[\d.]+/([\d.]+)/", result.stdout)
    assert match, f"could not read RTT from:\n{result.stdout}"
    return float(match.group(1))


@pytest.fixture(scope="module")
def pair_endpoints(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    """A running pair plus the (container, interface) pairs to shape."""
    out = tmp_path_factory.mktemp("netem")
    with running_pair(out) as ctx:
        endpoints = [
            (ctx.left_gateway, interface_holding(ctx.left_gateway, LEFT_TRANSIT)),
            (ctx.right_gateway, interface_holding(ctx.right_gateway, RIGHT_TRANSIT)),
        ]
        yield ctx, endpoints


def test_baseline_rtt_is_low(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    ctx, endpoints = pair_endpoints
    for container, interface in endpoints:
        clear(container, interface)
    assert measure_rtt_ms(ctx.left_gateway, RIGHT_TRANSIT) < 20.0


def test_wan_poor_raises_rtt_above_one_hundred_and_forty_ms(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    """80 ms of egress delay on each gateway, so the round trip carries both."""
    ctx, endpoints = pair_endpoints
    with impaired(endpoints, profile("wan_poor")):
        rtt = measure_rtt_ms(ctx.left_gateway, RIGHT_TRANSIT)
    assert rtt > 140.0, f"wan_poor produced only {rtt:.1f} ms RTT"


def test_removing_the_qdisc_restores_baseline_rtt(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    ctx, endpoints = pair_endpoints
    with impaired(endpoints, profile("wan_poor")):
        assert measure_rtt_ms(ctx.left_gateway, RIGHT_TRANSIT) > 140.0
    restored = measure_rtt_ms(ctx.left_gateway, RIGHT_TRANSIT)
    assert restored < 20.0, f"RTT stayed at {restored:.1f} ms after removal"


def test_teardown_is_idempotent(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    """Teardown runs in a finally block that may fire after the qdisc is already gone."""
    _ctx, endpoints = pair_endpoints
    container, interface = endpoints[0]
    clear(container, interface)
    clear(container, interface)
    clear(container, interface)


def test_applying_a_profile_installs_a_netem_qdisc(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    _ctx, endpoints = pair_endpoints
    container, interface = endpoints[0]
    with impaired(endpoints, profile("wan_good")):
        assert "netem" in active_qdisc(container, interface)
    assert "netem" not in active_qdisc(container, interface)


def test_clean_profile_leaves_no_shaping(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    """ "clean" must mean an unshaped path, not netem with zeroed parameters."""
    _ctx, endpoints = pair_endpoints
    container, interface = endpoints[0]
    apply_profile(endpoints, profile("clean"))
    assert "netem" not in active_qdisc(container, interface)


def test_impairment_is_removed_even_when_the_block_raises(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    """A leaked qdisc silently distorts every later cell in a sweep."""
    _ctx, endpoints = pair_endpoints
    container, interface = endpoints[0]
    with pytest.raises(RuntimeError, match="deliberate"), impaired(endpoints, profile("wan_poor")):
        raise RuntimeError("deliberate failure inside the impaired block")
    assert "netem" not in active_qdisc(container, interface)


def test_satellite_profile_produces_the_highest_latency(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    ctx, endpoints = pair_endpoints
    with impaired(endpoints, profile("satellite")):
        rtt = measure_rtt_ms(ctx.left_gateway, RIGHT_TRANSIT, count=4)
    assert rtt > 500.0, f"satellite produced only {rtt:.1f} ms RTT"


# The heaviest profile loses 2% of packets, so a sample has to be large enough that
# seeing none of them is not simply bad luck. At 60 packets P(zero losses) = 0.98^60,
# about **30%** — the test failed one run in three and had been passing on luck. At 400
# it is 0.98^400, about 0.03%.
LOSS_SAMPLE_PACKETS = 400


def test_loss_is_actually_applied(pair_endpoints) -> None:  # type: ignore[no-untyped-def]
    """The impairment must reach the wire, not just the qdisc listing."""
    ctx, endpoints = pair_endpoints
    heavy = profile("satellite")
    with impaired(endpoints, heavy):
        result = exec_in(
            ctx.left_gateway,
            "ping",
            "-c",
            str(LOSS_SAMPLE_PACKETS),
            "-i",
            "0.05",
            "-W",
            "2",
            RIGHT_TRANSIT,
            timeout=180,
        )

    # Counted, not read off the percentage: ping truncates, so one loss in 400 prints as
    # "0% packet loss" and a percentage test would call that no loss at all.
    match = re.search(
        r"(\d+) packets transmitted,\s+(\d+)(?:\s+packets)?\s+received", result.stdout
    )
    assert match, result.stdout
    transmitted, received = int(match.group(1)), int(match.group(2))
    lost = transmitted - received

    assert transmitted == LOSS_SAMPLE_PACKETS, result.stdout
    assert lost > 0, f"no loss observed under a {heavy.loss_pct}% profile: {result.stdout}"
    assert received > 0, f"every packet was dropped, which is not shaping: {result.stdout}"

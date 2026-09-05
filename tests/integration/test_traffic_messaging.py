"""Messaging generator over a live tunnel (build plan Step 2.7).

The class is XMPP standing in for consumer messaging. That substitution is asserted
here as well as documented, because the honesty is part of the deliverable.
"""

from __future__ import annotations

import itertools
import statistics
from pathlib import Path

import pytest
from scapy.all import IP, TCP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.messaging import (
    PROXY_DISCLOSURE,
    VARIANTS,
    XMPP_ORIGIN_IP,
    MessagingGenerator,
    generate_account_password,
)

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
DURATION_S = 40


@pytest.fixture(scope="module")
def chat_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path]:
    out = tmp_path_factory.mktemp("messaging")
    password = generate_account_password()
    with running_pair(out, profiles=("messaging",), extra_env={"XMPP_PASSWORD": password}) as ctx:
        gen = MessagingGenerator("chat_active", password=password, seed=4)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        gen.teardown()
        return outcome, capture.inner_pcap


def xmpp_packets(path: Path) -> list:  # type: ignore[type-arg]
    with PcapReader(str(path)) as reader:
        return [
            p
            for p in reader
            if p.haslayer(TCP)
            and p.haslayer(IP)
            and XMPP_ORIGIN_IP in (p[IP].src, p[IP].dst)
            and len(p[TCP].payload) > 0
        ]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(MessagingGenerator(password="x"), TrafficGenerator)


def test_class_label_is_messaging() -> None:
    """The plan requires this exact label."""
    assert MessagingGenerator(password="x").name == "messaging"


def test_the_proxy_substitution_is_declared_not_implied() -> None:
    """A claimed WhatsApp corpus would be indefensible; the substitution is stated."""
    import testbed.traffic.messaging as messaging_module

    assert "XMPP" in PROXY_DISCLOSURE
    assert "not" in PROXY_DISCLOSURE and "WhatsApp" in PROXY_DISCLOSURE
    module_doc = (messaging_module.__doc__ or "").lower()
    assert "proxy" in module_doc
    assert "whatsapp" in module_doc, "the module must name what it is NOT"
    assert "not whatsapp" in module_doc


def test_setup_without_a_password_is_rejected() -> None:
    from testbed.traffic.base import RunContext

    ctx = RunContext(
        project="p",
        left_gateway="a",
        right_gateway="b",
        left_host="c",
        right_host="d",
        left_host_ip="10.1.0.10",
        right_host_ip="10.2.0.10",
        out_dir=Path("/tmp"),
    )
    with pytest.raises(RuntimeError, match="password"):
        MessagingGenerator("chat_active").setup(ctx)


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown messaging variant"):
        MessagingGenerator("sms")


def test_run_reports_a_two_way_conversation(chat_run: tuple[object, Path]) -> None:
    outcome, _ = chat_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]
    assert outcome.packets_sent >= 4  # type: ignore[attr-defined]


def test_packets_are_small(chat_run: tuple[object, Path]) -> None:
    """Chat stanzas are tiny; anything MTU-sized would be a different class."""
    _, inner = chat_run
    sizes = [len(p) for p in xmpp_packets(inner)]
    assert len(sizes) >= 8, f"too few stanzas captured: {len(sizes)}"
    assert statistics.mean(sizes) < 600, f"mean packet size {statistics.mean(sizes):.0f}B too large"
    assert max(sizes) < 1400, "a near-MTU packet is not a chat message"


def test_gaps_are_irregular(chat_run: tuple[object, Path]) -> None:
    """Human pauses vary. A metronome would be VoIP, not conversation."""
    _, inner = chat_run
    times = sorted(float(p.time) for p in xmpp_packets(inner))
    gaps = [b - a for a, b in itertools.pairwise(times) if b - a > 0.05]
    assert len(gaps) >= 5, f"too few gaps to judge regularity: {len(gaps)}"
    assert statistics.pstdev(gaps) > 0.3, (
        f"gaps are too regular (stdev {statistics.pstdev(gaps):.2f}s) to be conversational"
    )


def test_traffic_is_roughly_symmetric(chat_run: tuple[object, Path]) -> None:
    """Both parties talk; a one-sided flow would not be a conversation."""
    _, inner = chat_run
    packets = xmpp_packets(inner)
    up = sum(len(p) for p in packets if p[IP].dst == XMPP_ORIGIN_IP)
    down = sum(len(p) for p in packets if p[IP].src == XMPP_ORIGIN_IP)
    assert up > 0 and down > 0
    ratio = up / down
    assert 0.25 <= ratio <= 4.0, f"upstream/downstream ratio {ratio:.2f} is one-sided"


def test_variants_differ_in_pacing() -> None:
    assert len({(v.gap_min_s, v.gap_max_s) for v in VARIANTS.values()}) == 2

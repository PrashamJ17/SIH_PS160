"""One full testbed cycle, end to end (build plan milestone M1).

This is the M1 manual acceptance criterion turned into a test, so the properties it
checks cannot silently regress between here and the Phase 3 sweep.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import ICMP, IP, UDP, PcapReader

from testbed.orchestrate.single_run import config_for_label, run_once

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image"),
]


@pytest.fixture(scope="module")
def cycle(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path]:
    out = tmp_path_factory.mktemp("single_run")
    manifest = run_once(config_for_label("weak"), out, label="weak", ping_count=6)
    return manifest, out


def packets(path: Path) -> list[object]:
    with PcapReader(str(path)) as reader:
        return list(reader)


def test_tunnel_establishes(cycle: tuple[object, Path]) -> None:
    manifest, _ = cycle
    assert manifest.negotiated_ike is not None  # type: ignore[attr-defined]
    assert manifest.negotiated_ike.established is True  # type: ignore[attr-defined]


def test_negotiation_matched_intent(cycle: tuple[object, Path]) -> None:
    manifest, _ = cycle
    assert manifest.negotiation_matched_intent is True, manifest.mismatches  # type: ignore[attr-defined]


def test_manifest_records_negotiated_not_intended_values(cycle: tuple[object, Path]) -> None:
    """The label must come from what the peers agreed, not from the config file."""
    manifest, _ = cycle
    assert manifest.intent["encryption"] == "aes128"  # type: ignore[attr-defined]
    assert manifest.negotiated_ike.encryption == "AES_CBC"  # type: ignore[attr-defined]
    assert manifest.negotiated_ike.encryption_keylen == 128  # type: ignore[attr-defined]
    assert manifest.negotiated_ike.dh_group == "MODP_1024"  # type: ignore[attr-defined]


def test_kernel_confirms_two_sas(cycle: tuple[object, Path]) -> None:
    manifest, _ = cycle
    assert len(manifest.kernel_sas) == 2  # type: ignore[attr-defined]


def test_manifest_file_is_written(cycle: tuple[object, Path]) -> None:
    _, out = cycle
    assert (out / "manifest.json").stat().st_size > 0


def test_outer_pcap_contains_the_ike_handshake(cycle: tuple[object, Path]) -> None:
    """The regression guard for M1's defect.

    The handshake happens exactly once, during initiation. If capture starts after
    that, the corpus is ESP with no negotiation to parse — which looks fine until the
    parser lane discovers it has nothing to read.
    """
    _, out = cycle
    ike = [
        p
        for p in packets(out / "capture_outer.pcap")
        if p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500))
    ]
    assert len(ike) >= 2, "outer capture contains no IKE — capture started too late"


def test_outer_pcap_contains_esp(cycle: tuple[object, Path]) -> None:
    _, out = cycle
    esp = [p for p in packets(out / "capture_outer.pcap") if p.haslayer(IP) and p[IP].proto == 50]
    assert len(esp) >= 6


def test_outer_pcap_contains_no_plaintext(cycle: tuple[object, Path]) -> None:
    _, out = cycle
    icmp = [p for p in packets(out / "capture_outer.pcap") if p.haslayer(ICMP)]
    assert icmp == [], "plaintext ICMP in the outer capture"


def test_inner_pcap_contains_plaintext_both_directions(cycle: tuple[object, Path]) -> None:
    _, out = cycle
    icmp = [p for p in packets(out / "capture_inner.pcap") if p.haslayer(ICMP)]
    assert len([p for p in icmp if p[ICMP].type == 8]) >= 5
    assert len([p for p in icmp if p[ICMP].type == 0]) >= 5


def test_unknown_label_is_rejected() -> None:
    from testbed.orchestrate.single_run import RunError

    with pytest.raises(RunError, match="unknown config label"):
        config_for_label("nonexistent")

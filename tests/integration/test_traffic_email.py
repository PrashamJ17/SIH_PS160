"""Email generator over a live tunnel (build plan Step 2.6).

Traffic is genuine SMTP and IMAP against real Postfix and Dovecot, so what lands in
the corpus is actual protocol rather than an imitation of it.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from scapy.all import IP, TCP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.email import (
    MAIL_ORIGIN_IP,
    VARIANTS,
    EmailGenerator,
    generate_mailbox_password,
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


def _run(variant: str, out: Path) -> tuple[object, Path, int]:
    password = generate_mailbox_password()
    with running_pair(out, profiles=("mail",), extra_env={"MAIL_PASSWORD": password}) as ctx:
        gen = EmailGenerator(variant, password=password, seed=5)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        largest = gen.largest_burst_bytes
        gen.teardown()
        return outcome, capture.inner_pcap, largest


@pytest.fixture(scope="module")
def small_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, int]:
    return _run("smtp_small", tmp_path_factory.mktemp("mail_small"))


@pytest.fixture(scope="module")
def attachment_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, int]:
    return _run("smtp_attachment", tmp_path_factory.mktemp("mail_attach"))


def mail_packets(path: Path) -> list:  # type: ignore[type-arg]
    with PcapReader(str(path)) as reader:
        return [
            p
            for p in reader
            if p.haslayer(TCP) and p.haslayer(IP) and MAIL_ORIGIN_IP in (p[IP].src, p[IP].dst)
        ]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(EmailGenerator(password="x"), TrafficGenerator)


def test_generator_declares_the_mail_sidecar_it_requires() -> None:
    assert "mail" in EmailGenerator(password="x").requires


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown email variant"):
        EmailGenerator("pop3")


def test_setup_without_a_password_is_rejected() -> None:
    """The mailbox password is generated per run, never stored."""
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
        EmailGenerator("smtp_small").setup(ctx)


def test_generated_passwords_are_unique() -> None:
    assert generate_mailbox_password() != generate_mailbox_password()


def test_smtp_small_run_succeeds(small_run: tuple[object, Path, int]) -> None:
    outcome, _, _ = small_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]


def test_traffic_is_mostly_idle_with_discrete_bursts(
    small_run: tuple[object, Path, int],
) -> None:
    """Long silence between short exchanges — unlike streaming or VoIP."""
    _, inner, _ = small_run
    times = sorted(float(p.time) for p in mail_packets(inner))
    assert len(times) > 10, f"too few mail packets: {len(times)}"
    gaps = [b - a for a, b in itertools.pairwise(times)]
    idle = sum(g for g in gaps if g > 1.0)
    span = times[-1] - times[0]
    assert span > 0
    assert idle / span >= 0.5, f"link idle only {idle / span:.0%} of the time — not bursty"
    assert len([g for g in gaps if g > 2.0]) >= 2, "no discrete bursts separated by silence"


def test_attachment_variant_produces_a_burst_above_one_hundred_kilobytes(
    attachment_run: tuple[object, Path, int],
) -> None:
    outcome, inner, largest = attachment_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]
    assert largest > 100_000, f"largest message only {largest} bytes"
    upstream = sum(len(p) for p in mail_packets(inner) if p[IP].dst == MAIL_ORIGIN_IP)
    assert upstream > 100_000, f"only {upstream} bytes sent to the mail server"


def test_attachment_variant_is_upstream_heavy(
    attachment_run: tuple[object, Path, int],
) -> None:
    """Sending mail inverts the usual asymmetry: the client is the one uploading."""
    _, inner, _ = attachment_run
    packets = mail_packets(inner)
    up = sum(len(p) for p in packets if p[IP].dst == MAIL_ORIGIN_IP)
    down = sum(len(p) for p in packets if p[IP].src == MAIL_ORIGIN_IP)
    assert down > 0
    assert up > down, f"upstream {up} not greater than downstream {down}"


@pytest.fixture(scope="module")
def imap_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, int]:
    return _run("imap_sync", tmp_path_factory.mktemp("mail_imap"))


def test_imap_sync_variant_actually_polls_a_real_mailbox(
    imap_run: tuple[object, Path, int],
) -> None:
    """Exercises the IMAP path end to end against Dovecot.

    Without this the variant would be untested code that only failed mid-sweep.
    """
    outcome, inner, _ = imap_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]
    assert outcome.packets_sent >= 2  # type: ignore[attr-defined]
    imap = [p for p in mail_packets(inner) if 143 in (p[TCP].sport, p[TCP].dport)]
    assert imap, "no traffic on the IMAP port — the poll never reached Dovecot"


def test_imap_sync_is_download_heavy(imap_run: tuple[object, Path, int]) -> None:
    """Polling fetches messages, so the client is the one receiving."""
    _, inner, _ = imap_run
    imap = [p for p in mail_packets(inner) if 143 in (p[TCP].sport, p[TCP].dport)]
    down = sum(len(p) for p in imap if p[IP].src == MAIL_ORIGIN_IP)
    up = sum(len(p) for p in imap if p[IP].dst == MAIL_ORIGIN_IP)
    assert up > 0 and down > up, f"IMAP downstream {down} not greater than upstream {up}"


def test_variants_cover_send_and_poll() -> None:
    modes = {v.mode for v in VARIANTS.values()}
    assert modes == {"smtp_small", "smtp_attachment", "imap_sync"}

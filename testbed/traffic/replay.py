"""External PCAP replay generator.

This is the move that makes the problem statement's named datasets genuinely usable.
CIC-IDS2017, UNSW-NB15, CTU-13 and the rest contain no IPsec at all — Step 3.5 proves
it — but their benign traffic is real traffic, captured from real applications. Replay
it through a tunnel as inner payload and the corpus gets authentic packet-size and
burst structure while our own configuration supplies the crypto labels.

That reframes an apparent shortfall into the only technically sound way to use those
datasets here, and it is worth saying out loud: we did use them, as payload, because
they contain nothing else this problem can use.

Replay preserves packet sizes faithfully. It distorts inter-arrival timing according
to the replay rate, which is a real limitation and belongs in docs/DATASET.md.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext

REPLAY_DIR: Final = "/tmp/sentinel_replay"


@dataclass(frozen=True)
class ReplayVariant:
    """One external source corpus, replayed at a chosen rate."""

    name: str
    dataset_key: str
    rate_mbps: float


VARIANTS: Final[dict[str, ReplayVariant]] = {
    "cicids2017_benign": ReplayVariant(
        "cicids2017_benign", dataset_key="cicids2017", rate_mbps=5.0
    ),
    "mawi_sample": ReplayVariant("mawi_sample", dataset_key="mawi", rate_mbps=10.0),
}


class ReplaySourceMissingError(RuntimeError):
    """The external capture to replay is not present."""


class ReplayGenerator:
    """Replay an external capture through the tunnel as inner payload.

    The source's addresses are rewritten so the packets route through the gateway;
    everything else about them — sizes, protocol mix, burst structure — is preserved.
    """

    name = "replay"
    requires: ClassVar[list[str]] = []

    def __init__(
        self,
        variant: str = "cicids2017_benign",
        source_pcap: Path | None = None,
        rate_mbps: float | None = None,
    ) -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown replay variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self.source_pcap = source_pcap
        self.rate_mbps = rate_mbps or self.variant.rate_mbps
        self.rewritten_packets = 0
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        if self.source_pcap is None or not Path(self.source_pcap).exists():
            raise ReplaySourceMissingError(
                f"replay source for {self.variant.name} is missing "
                f"({self.source_pcap}). External corpora require manual download; see "
                f"scripts/fetch_external.py and docs/DATASET.md."
            )
        self._ctx = ctx
        self._prepare(ctx)

    def teardown(self) -> None:
        self._ctx = None

    def _exec(
        self, container: str, *cmd: str, timeout: int = 300
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "exec", container, *cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _mac_of(self, container: str, address: str) -> str:
        """The MAC on the interface holding ``address``."""
        out = self._exec(
            container,
            "sh",
            "-c",
            f"ip -o link show \"$(ip -o -4 addr show | awk '$4 ~ /^{address}\\//"
            f" {{print $2}}' | head -1)\"",
        ).stdout
        match = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
        if not match:
            raise RuntimeError(f"could not read the MAC for {address} in {container}")
        return match.group(1)

    def _prepare(self, ctx: RunContext) -> None:
        """Copy the source in and rewrite its addresses for this topology.

        Both IPs and MACs must be rewritten. Without the destination MAC pointing at
        the gateway the replayed frames are never forwarded, and without the IP remap
        they do not match the tunnel's traffic selectors — either way the packets go
        nowhere and the cell looks empty.
        """
        assert self.source_pcap is not None
        self._exec(ctx.left_host, "mkdir", "-p", REPLAY_DIR)
        copied = subprocess.run(
            ["docker", "cp", str(self.source_pcap), f"{ctx.left_host}:{REPLAY_DIR}/source.pcap"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if copied.returncode != 0:
            raise RuntimeError(f"could not copy the replay source in: {copied.stderr.strip()}")

        src_mac = self._mac_of(ctx.left_host, ctx.left_host_ip)
        gw_mac = self._mac_of(ctx.left_gateway, "10.1.0.2")

        rewrite = self._exec(
            ctx.left_host,
            "tcprewrite",
            f"--infile={REPLAY_DIR}/source.pcap",
            f"--outfile={REPLAY_DIR}/rewritten.pcap",
            f"--srcipmap=0.0.0.0/0:{ctx.left_host_ip}/32",
            f"--dstipmap=0.0.0.0/0:{ctx.right_host_ip}/32",
            f"--enet-smac={src_mac}",
            f"--enet-dmac={gw_mac}",
            "--fixcsum",
        )
        if rewrite.returncode != 0:
            raise RuntimeError(f"tcprewrite failed: {rewrite.stderr.strip()[:300]}")

        counted = self._exec(
            ctx.left_host,
            "sh",
            "-c",
            f"tcpdump -r {REPLAY_DIR}/rewritten.pcap -n 2>/dev/null | wc -l",
        )
        self.rewritten_packets = int(counted.stdout.strip() or 0)

    def run(self, duration_s: int) -> GenerationResult:
        if self._ctx is None:
            raise RuntimeError("setup() must be called before run()")
        ctx = self._ctx

        interface = self._exec(
            ctx.left_host,
            "sh",
            "-c",
            f"ip -o -4 addr show | awk '$4 ~ /^{ctx.left_host_ip}\\// {{print $2}}' | head -1",
        ).stdout.strip()
        if not interface:
            raise RuntimeError(f"no interface in the left host holds {ctx.left_host_ip}")

        started = datetime.now(UTC)
        completed = self._exec(
            ctx.left_host,
            "tcpreplay",
            f"--intf1={interface}",
            f"--mbps={self.rate_mbps}",
            f"{REPLAY_DIR}/rewritten.pcap",
            timeout=duration_s + 300,
        )
        ended = datetime.now(UTC)

        sent, bytes_sent = _parse_tcpreplay(completed.stdout + completed.stderr)
        if sent == 0:
            detail = (completed.stderr.strip() or completed.stdout.strip())[:250]
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=ended,
                success=False,
                error=f"tcpreplay sent nothing (exit {completed.returncode}): {detail}",
            )
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=sent,
            bytes_sent=bytes_sent,
            started_at=started,
            ended_at=ended,
            success=True,
        )


def _parse_tcpreplay(output: str) -> tuple[int, int]:
    """Read the packet and byte counts from tcpreplay's summary."""
    packets = match_bytes = 0
    packet_match = re.search(r"Successful packets:\s+(\d+)", output)
    if packet_match:
        packets = int(packet_match.group(1))
    bytes_match = re.search(r"Actual:\s+(\d+)\s+packets\s+\((\d+)\s+bytes\)", output)
    if bytes_match:
        packets = packets or int(bytes_match.group(1))
        match_bytes = int(bytes_match.group(2))
    return packets, match_bytes

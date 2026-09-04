"""Simultaneous encrypted and plaintext capture.

The outer tap watches the transit link and sees what a passive observer sees: IKE and
ESP. The inner tap watches a gateway's protected interface and sees the cleartext,
which is what gives every flow a perfect application label.

Two design points are load-bearing and easy to get wrong:

**The inner tap must watch forwarded traffic, not gateway-generated traffic.** A packet
a gateway originates never crosses its own protected interface, so capturing there
while pinging *from the gateway* yields only the inbound decrypted half. It looks like
it works and is badly wrong as training data, since every directional feature is
computed from half a conversation. Hosts sit behind each gateway for this reason.

**tcpdump buffers.** A capture that is killed rather than terminated loses whatever is
still buffered, producing a short file with no error anywhere. Every capture here is
stopped with SIGTERM, waited on until the process is genuinely gone, and then verified
to be non-empty and readable end to end.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final

from testbed.orchestrate.dockerutil import exec_in_container

# What a passive observer of the transit link can see. Deliberately narrow: widening it
# would admit the decrypted copies the kernel re-injects on the capturing host, putting
# plaintext into the outer capture.
OUTER_BPF: Final = "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50"
# The protected side is captured whole; that is the point of the inner tap.
INNER_BPF: Final = ""

_STOP_TIMEOUT_S: Final = 20.0
_POLL_INTERVAL_S: Final = 0.1


class CaptureError(RuntimeError):
    """A capture failed to start, stop, or produced an unusable file."""


@dataclass(frozen=True)
class CaptureSpec:
    """One tcpdump: where to run it, what to watch, and what to filter."""

    container: str
    interface: str
    bpf: str
    remote_path: str
    name: str


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


class _Tap:
    """A single running tcpdump inside a container."""

    def __init__(self, spec: CaptureSpec) -> None:
        self.spec = spec
        self._pid: str | None = None

    @property
    def _pid_path(self) -> str:
        return f"{self.spec.remote_path}.pid"

    def start(self) -> None:
        """Launch tcpdump and record its PID so it can be signalled later.

        The PID file exists because procps is not in the image: without pkill, the
        only way to deliver SIGTERM to the right process is to have kept its PID.
        """
        filter_clause = f" '{self.spec.bpf}'" if self.spec.bpf else ""
        command = (
            f"tcpdump -i {self.spec.interface} -n -U -s 0 "
            f"-w {self.spec.remote_path}{filter_clause} & "
            f"echo $! > {self._pid_path}; wait"
        )
        result = _docker("exec", "-d", self.spec.container, "sh", "-c", command)
        if result.returncode != 0:
            raise CaptureError(f"could not start {self.spec.name} tap: {result.stderr.strip()}")
        self._await_pid()

    def _await_pid(self) -> None:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            got = _docker("exec", self.spec.container, "sh", "-c", f"cat {self._pid_path}")
            if got.returncode == 0 and got.stdout.strip().isdigit():
                self._pid = got.stdout.strip()
                return
            time.sleep(_POLL_INTERVAL_S)
        raise CaptureError(f"{self.spec.name} tap never reported a PID")

    def wait_until_capturing(self, timeout: float = 10.0) -> None:
        """Block until the capture file exists, so no traffic is missed at the start."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            probe = _docker("exec", self.spec.container, "test", "-f", self.spec.remote_path)
            if probe.returncode == 0:
                return
            time.sleep(_POLL_INTERVAL_S)
        raise CaptureError(f"{self.spec.name} capture file never appeared")

    def stop(self) -> None:
        """SIGTERM, then wait for the process to actually exit and flush.

        The signal goes through ``sh -c`` deliberately. The image has no procps, so
        there is no ``/bin/kill`` binary, and ``docker exec <c> kill ...`` does not
        invoke a shell — it fails, silently, and the capture is then truncated by the
        container teardown instead of being flushed. ``kill`` is a shell builtin, so a
        shell always has it. (``test`` needs no such care: coreutils provides
        ``/usr/bin/test``.)
        """
        if self._pid is None:
            return
        _docker("exec", self.spec.container, "sh", "-c", f"kill -TERM {self._pid}")
        deadline = time.monotonic() + _STOP_TIMEOUT_S
        while time.monotonic() < deadline:
            alive = _docker("exec", self.spec.container, "test", "-d", f"/proc/{self._pid}")
            if alive.returncode != 0:
                return
            time.sleep(_POLL_INTERVAL_S)
        raise CaptureError(
            f"{self.spec.name} tcpdump did not exit within {_STOP_TIMEOUT_S}s; the "
            f"capture may be truncated"
        )

    def collect(self, destination: Path) -> Path:
        """Copy the capture out of the container."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = _docker(
            "cp",
            f"{self.spec.container}:{self.spec.remote_path}",
            str(destination),
            timeout=180,
        )
        if result.returncode != 0:
            raise CaptureError(f"could not collect {self.spec.name}: {result.stderr.strip()}")
        return destination


def _walk_pcap_records(path: Path) -> int:
    """Structurally verify a classic pcap and count its records.

    Scapy stops silently at end of file, so a capture whose final packet was cut off
    reads back as a shorter capture with no error at all — the exact silent corruption
    a killed-rather-than-terminated tcpdump produces. This walks the record headers and
    insists every declared packet is actually present.

    Returns -1 for formats this cannot walk (pcapng), leaving verification to scapy.
    """
    data = path.read_bytes()
    if len(data) < 24:
        raise CaptureError(f"{path} is shorter than a pcap file header")

    magic = data[:4]
    if magic in (b"\x0a\x0d\x0d\x0a",):
        return -1  # pcapng: not walked here
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise CaptureError(f"{path} does not start with a pcap magic number")

    offset = 24
    count = 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise CaptureError(
                f"{path} is truncated: a packet record header is cut off at byte {offset}"
            )
        incl_len = int.from_bytes(
            data[offset + 8 : offset + 12], "little" if endian == "<" else "big"
        )
        offset += 16
        if offset + incl_len > len(data):
            raise CaptureError(
                f"{path} is truncated: record {count} declares {incl_len} bytes but only "
                f"{len(data) - offset} remain"
            )
        offset += incl_len
        count += 1
    return count


def verify_pcap(path: Path, *, require_packets: bool = True) -> int:
    """Verify a capture is complete and readable, returning its packet count.

    Two independent checks, because each catches what the other misses: a structural
    walk of the record headers detects a truncated final packet, and a full scapy read
    detects a file that is structurally intact but not parseable.
    """
    if not path.exists():
        raise CaptureError(f"{path} does not exist")
    if path.stat().st_size == 0:
        raise CaptureError(f"{path} is empty")

    structural = _walk_pcap_records(path)

    # Import from scapy.all so the layer registry is populated; importing scapy.utils
    # alone leaves DLT 1 unmapped and every packet is read as Raw.
    from scapy.all import PcapReader

    count = 0
    try:
        with PcapReader(str(path)) as reader:
            for _ in reader:
                count += 1
    except Exception as exc:
        raise CaptureError(f"{path} is not readable end to end: {exc}") from exc

    if structural >= 0 and structural != count:
        raise CaptureError(
            f"{path} is inconsistent: {structural} records on disk but scapy read {count}"
        )
    if require_packets and count == 0:
        raise CaptureError(f"{path} contains no packets")
    return count


class DualCapture:
    """Run the outer and inner taps together for the duration of a block."""

    def __init__(
        self,
        outer: CaptureSpec,
        inner: CaptureSpec,
        out_dir: Path,
        *,
        settle_s: float = 1.0,
    ) -> None:
        self._outer_tap = _Tap(outer)
        self._inner_tap = _Tap(inner)
        self._out_dir = out_dir
        self._settle_s = settle_s
        self._outer_pcap = out_dir / f"{outer.name}.pcap"
        self._inner_pcap = out_dir / f"{inner.name}.pcap"
        self._collected = False

    @property
    def outer_pcap(self) -> Path:
        return self._outer_pcap

    @property
    def inner_pcap(self) -> Path:
        return self._inner_pcap

    def __enter__(self) -> DualCapture:
        self._outer_tap.start()
        self._inner_tap.start()
        self._outer_tap.wait_until_capturing()
        self._inner_tap.wait_until_capturing()
        # tcpdump reports it is ready slightly before the kernel filter is attached.
        time.sleep(self._settle_s)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Let in-flight packets reach the capture before signalling.
        time.sleep(self._settle_s)
        errors: list[str] = []
        for tap in (self._outer_tap, self._inner_tap):
            try:
                tap.stop()
            except CaptureError as stop_error:
                errors.append(str(stop_error))
        try:
            self._outer_tap.collect(self._outer_pcap)
            self._inner_tap.collect(self._inner_pcap)
            self._collected = True
        except CaptureError as collect_error:
            errors.append(str(collect_error))
        if errors and exc_type is None:
            raise CaptureError("; ".join(errors))

    def verify(self, *, require_inner_packets: bool = True) -> tuple[int, int]:
        """Confirm both captures are usable, returning their packet counts."""
        if not self._collected:
            raise CaptureError("captures were not collected; use DualCapture as a context manager")
        return (
            verify_pcap(self._outer_pcap),
            verify_pcap(self._inner_pcap, require_packets=require_inner_packets),
        )


def interface_holding(container: str, address: str) -> str:
    """Name the interface carrying ``address``.

    Docker's network attachment order is not guaranteed, so interface names are always
    resolved from the address rather than assumed.
    """
    output = exec_in_container(
        container,
        "sh",
        "-c",
        f"ip -o -4 addr show | awk '$4 ~ /^{address}\\// {{print $2}}'",
    )
    names = [line.strip() for line in output.splitlines() if line.strip()]
    if not names:
        raise CaptureError(f"no interface in {container} holds {address}")
    return names[0]


def dual_capture_for_pair(
    gateway: str,
    transit_address: str,
    protected_address: str,
    out_dir: Path,
    *,
    prefix: str = "capture",
) -> DualCapture:
    """Build a :class:`DualCapture` for one gateway of a testbed pair."""
    if shutil.which("docker") is None:
        raise CaptureError("docker is not available")
    return DualCapture(
        outer=CaptureSpec(
            container=gateway,
            interface=interface_holding(gateway, transit_address),
            bpf=OUTER_BPF,
            remote_path=f"/tmp/{prefix}_outer.pcap",
            name=f"{prefix}_outer",
        ),
        inner=CaptureSpec(
            container=gateway,
            interface=interface_holding(gateway, protected_address),
            bpf=INNER_BPF,
            remote_path=f"/tmp/{prefix}_inner.pcap",
            name=f"{prefix}_inner",
        ),
        out_dir=out_dir,
    )

"""A live strongSwan pair whose configuration can be edited and reloaded in place.

Extracted from ``tests/integration/test_sequence_live.py`` at Step 8.6, when a second
integration test needed the same thing. Editing the file the container has bind-mounted
and running ``swanctl --load-all`` is deliberately what an operator does: the change
packages tell them to edit a config and reload, and a harness that instead poked the
daemon through some other door would not be exercising those instructions.
"""

from __future__ import annotations

import base64
import re
import secrets
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from testbed.orchestrate.capture import DualCapture, dual_capture_for_pair
from testbed.orchestrate.config_gen import Role, TunnelConfig, render_swanctl_conf
from tests.fixtures.dockerctl import compose, compose_project, exec_in

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PAIR_COMPOSE: Final = REPO_ROOT / "testbed" / "compose" / "pair.yml"
LEFT_HOST_IP: Final = "10.1.0.10"
RIGHT_HOST_IP: Final = "10.2.0.10"
LEFT_TRANSIT_IP: Final = "10.100.0.2"
LEFT_PROTECTED_IP: Final = "10.1.0.2"
PROBE_LOG: Final = "/tmp/sequence-probe.log"
PROBE_INTERVAL_S: Final = 0.2
PROBE_TIMEOUT_S: Final = 1
SETTLE_S: Final = 3
# The probe must have been running for essentially the whole change, or its verdict
# only covers the part it happened to be awake for.
MIN_PROBE_COVERAGE: Final = 0.95
# The negative control has to show an unmistakable, sustained outage rather than one
# stray drop, or it does not establish that the instrument can read non-zero. Measured
# as a duration because that is what an operator experiences and, unlike a probe count,
# it does not depend on the sampling rate.
MIN_CONTROL_OUTAGE_S: Final = 0.5


# --------------------------------------------------------------------------- reading


@dataclass(frozen=True)
class LiveSa:
    """One established IKE SA and the child SAs installed under it."""

    ike_id: int
    ike_algorithms: str
    esp_algorithms: tuple[str, ...]

    def carries(self, config: TunnelConfig) -> bool:
        """Whether this SA negotiated the crypto ``config`` asks for.

        Compared through strongSwan's own rendering of the algorithms rather than the
        proposal string, because the proposal string is what we *asked* for and this
        has to answer what was *agreed*.
        """
        return _kernel_names(config) == _normalise(self.ike_algorithms)


def _normalise(algorithms: str) -> frozenset[str]:
    return frozenset(part.replace("-", "_").upper() for part in algorithms.split("/"))


_KERNEL_NAME: Final[dict[str, str]] = {
    "aes128": "AES_CBC_128",
    "aes256": "AES_CBC_256",
    "aes256gcm16": "AES_GCM_16_256",
    "3des": "3DES_CBC",
    "sha1": "HMAC_SHA1_96",
    "sha256": "HMAC_SHA2_256_128",
    "sha384": "HMAC_SHA2_384_192",
    "md5": "HMAC_MD5_96",
    "prfsha1": "PRF_HMAC_SHA1",
    "prfsha256": "PRF_HMAC_SHA2_256",
    "prfsha384": "PRF_HMAC_SHA2_384",
    "prfmd5": "PRF_HMAC_MD5",
    "modp1024": "MODP_1024",
    "modp2048": "MODP_2048",
    "ecp384": "ECP_384",
    "curve25519": "CURVE_25519",
}


def _kernel_names(config: TunnelConfig) -> frozenset[str]:
    """The algorithm names strongSwan will print for this configuration's IKE SA."""
    parts = config.proposal_string().split("-")
    unknown = [p for p in parts if p not in _KERNEL_NAME]
    if unknown:
        raise AssertionError(
            f"no kernel name known for {unknown} in {config.proposal_string()!r}; "
            f"extend _KERNEL_NAME rather than loosening the comparison"
        )
    return frozenset(_KERNEL_NAME[p] for p in parts)


_SA_HEADER: Final = re.compile(r"^net-net: #(\d+), (\w+), IKEv\d")
_IKE_ALGORITHMS: Final = re.compile(r"^\s+(\S*/PRF_\S+/\S+)\s*$")
_ESP_ALGORITHMS: Final = re.compile(r"INSTALLED,.*ESP:(\S+)")


def parse_sas(listing: str) -> list[LiveSa]:
    """Read ``swanctl --list-sas`` into established SAs.

    Written by hand rather than with ``--raw`` because the human-readable form is what
    the change package's verification steps tell an operator to look at, and a parser
    that reads something else could pass while the instruction it validates does not.
    """
    sas: list[LiveSa] = []
    ike_id: int | None = None
    algorithms = ""
    esp: list[str] = []

    def flush() -> None:
        if ike_id is not None:
            sas.append(LiveSa(ike_id, algorithms, tuple(esp)))

    for line in listing.splitlines():
        header = _SA_HEADER.match(line)
        if header:
            flush()
            ike_id, algorithms, esp = (
                int(header.group(1)) if header.group(2) == "ESTABLISHED" else None,
                "",
                [],
            )
            continue
        if ike_id is None:
            continue
        if match := _IKE_ALGORITHMS.match(line):
            algorithms = match.group(1)
        elif match := _ESP_ALGORITHMS.search(line):
            esp.append(match.group(1))
    flush()
    return sas


# ---------------------------------------------------------------------- the live pair


@dataclass(frozen=True)
class Reachability:
    """A timestamped record of whether the far host answered, sample by sample.

    Deliberately not ``ping``'s own summary. iputils ``ping`` exits when the route to
    its target disappears, which is exactly the moment an outage begins — so it reports
    a clean run for the seconds before the failure and says nothing at all about the
    failure itself. That is the most dangerous possible instrument here: it returns
    "0% packet loss" precisely when the thing under test has broken. Sampling from a
    supervising loop keeps measuring across the gap, and timing every sample lets the
    result state how long it was actually watching and how long the outage lasted.
    """

    samples: tuple[tuple[float, bool], ...]
    block_s: float

    @property
    def sent(self) -> int:
        return len(self.samples)

    @property
    def lost(self) -> int:
        return sum(1 for _, ok in self.samples if not ok)

    @property
    def loss_percent(self) -> float:
        return 100.0 * self.lost / self.sent if self.sent else 100.0

    @property
    def measured_s(self) -> float:
        """Wall-clock span the probe actually covered."""
        return self.samples[-1][0] - self.samples[0][0] if self.sent > 1 else 0.0

    @property
    def coverage(self) -> float:
        return self.measured_s / self.block_s if self.block_s else 0.0

    @property
    def longest_outage_s(self) -> float:
        """Seconds between the last reply before the worst gap and the first after it.

        An upper bound on the outage, which is the right direction to err in for a
        claim that there was none.
        """
        worst = 0.0
        run_start: float | None = None
        previous_ok = self.samples[0][0] if self.sent else 0.0
        for timestamp, ok in self.samples:
            if ok:
                if run_start is not None:
                    worst = max(worst, timestamp - run_start)
                    run_start = None
                previous_ok = timestamp
            elif run_start is None:
                run_start = previous_ok
        if run_start is not None and self.sent:
            worst = max(worst, self.samples[-1][0] - run_start)
        return worst

    def summary(self) -> str:
        return (
            f"{self.sent} probes, {self.lost} lost ({self.loss_percent:.1f}%), "
            f"longest outage {self.longest_outage_s:.2f}s, watched "
            f"{self.measured_s:.1f}s of a {self.block_s:.1f}s change "
            f"({self.coverage:.0%} coverage)"
        )


def parse_probe(log: str) -> tuple[tuple[float, bool], ...]:
    samples: list[tuple[float, bool]] = []
    for line in log.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] not in ("ok", "lost"):
            continue
        try:
            samples.append((float(parts[0]), parts[1] == "ok"))
        except ValueError:  # a shell without %N would yield an unparseable stamp
            continue
    return tuple(samples)


class LivePair:
    """Two real peers whose configuration can be edited and reloaded in place.

    Editing the file the container has bind-mounted and reloading is deliberately the
    same thing an operator does — the change package tells them to edit a config and
    reload, and a test that instead poked the daemon through some other door would not
    be testing those instructions.
    """

    capture: DualCapture | None = None

    def __init__(
        self, config: TunnelConfig, containers: dict[str, str], confs: dict[Role, Path]
    ) -> None:
        self.config = config
        self.left = containers["left"]
        self.right = containers["right"]
        self.left_host = containers["left_host"]
        self._confs = confs

    def set_proposals(self, ike: str, esp: str) -> None:
        """Rewrite both ends' configuration files with these proposal lists."""
        for role, path in self._confs.items():
            text = render_swanctl_conf(self.config, role)
            text = re.sub(r"^(\s*)proposals = .*$", rf"\g<1>proposals = {ike}", text, flags=re.M)
            text = re.sub(
                r"^(\s*)esp_proposals = .*$", rf"\g<1>esp_proposals = {esp}", text, flags=re.M
            )
            # Truncate in place: replacing the file would swap the inode out from under
            # the bind mount and the container would keep reading the old one.
            path.write_text(text)

    def load(self, *, both_ends: bool = True) -> None:
        targets = (self.left, self.right) if both_ends else (self.left,)
        for container in targets:
            result = exec_in(container, "swanctl", "--load-all", timeout=90)
            assert result.returncode == 0, f"--load-all failed: {result.stderr[:300]}"

    def initiate(self) -> subprocess.CompletedProcess[str]:
        return exec_in(self.left, "swanctl", "--initiate", "--child", "net-net", timeout=180)

    def rekey_ike(self) -> subprocess.CompletedProcess[str]:
        """Renegotiate the IKE SA, putting a fresh IKE_SA_INIT on the wire.

        Used when the configuration has *not* changed. ``--initiate`` refuses to build a
        duplicate child SA with the same traffic selectors, so it cannot be used to
        produce a second handshake for an unchanged tunnel. A rekey can, and it is also
        how a watcher normally comes to see a long-lived tunnel's parameters.

        The counterpart matters just as much: after a configuration *change*, a rekey
        renegotiates the old parameters (established in Step 8.4), so ``initiate`` is the
        one that shows the new state.
        """
        return exec_in(self.left, "swanctl", "--rekey", "--ike", "net-net", timeout=120)

    def terminate(self, ike_id: int) -> None:
        exec_in(self.left, "swanctl", "--terminate", "--ike-id", str(ike_id), timeout=120)

    def sas(self, container: str | None = None) -> list[LiveSa]:
        listing = exec_in(container or self.left, "swanctl", "--list-sas", timeout=60).stdout
        return parse_sas(listing)

    def sa_carrying(self, config: TunnelConfig, container: str | None = None) -> LiveSa | None:
        return next((sa for sa in self.sas(container) if sa.carries(config)), None)

    # A self-contained sender, run with the container's own python3. The package is not
    # installed in the image, so this uses nothing but the standard library: the probe
    # is built on the host, sent from inside the network, and the reply comes back for
    # the host to interpret.
    _SENDER: Final = (
        "import base64, socket, sys\n"
        "payload = base64.b64decode(sys.argv[1])\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.settimeout(float(sys.argv[4]))\n"
        "try:\n"
        "    s.sendto(payload, (sys.argv[2], int(sys.argv[3])))\n"
        "    reply, _ = s.recvfrom(65535)\n"
        "    print(base64.b64encode(reply).decode())\n"
        "except Exception as exc:\n"
        "    print('ERR:' + type(exc).__name__)\n"
    )

    def set_config(self, config: TunnelConfig) -> None:
        """Replace both ends' configuration entirely, not just the proposal list.

        ``set_proposals`` edits the proposal lines of the config the pair was built
        from. Watching for drift needs a genuinely different configuration — a different
        cipher, group, and sometimes IKE version — so both files are re-rendered from
        the new :class:`TunnelConfig`. The topology and the PSK are unchanged, so the
        peers still address each other and still authenticate.
        """
        for role, path in self._confs.items():
            path.write_text(render_swanctl_conf(config, role))
        self.config = config

    def start_ike_capture(self, remote: str = "/tmp/ike.pcap") -> str:
        """Capture IKE only, inside the left gateway, for the life of the pair.

        Filtered to IKE because the transit interface is mostly ESP, and a watcher that
        re-reads a growing file should not be re-reading megabytes of payload it cannot
        decrypt.
        """
        exec_in(
            self.left,
            "sh",
            "-c",
            f"nohup tcpdump -i any -U -w {remote} 'udp port 500 or udp port 4500' "
            f">/dev/null 2>&1 &",
            timeout=30,
        )
        time.sleep(2)  # tcpdump reports ready slightly before the filter is attached
        return remote

    def fetch_capture(self, destination: Path, remote: str = "/tmp/ike.pcap") -> Path:
        """Copy the in-container capture out so a host-side watcher can read it."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["docker", "cp", f"{self.left}:{remote}", str(destination)],
            capture_output=True,
            timeout=60,
            check=False,
        )
        return destination

    def send_datagram(
        self, payload: bytes, target: str, port: int = 500, timeout_s: float = 3.0
    ) -> bytes | None:
        """Send one UDP datagram from inside the pair's network and return the reply.

        ``None`` means nothing came back. Used to put a probe in front of the live
        strongSwan responder, which is not reachable from the host: Docker Desktop does
        not route to container addresses.

        Sent from the **gateway**, not the host behind it. Only the gateways are on the
        transit network where the peer's IKE port lives; a datagram from the protected
        host has no route to it and is lost without an error, which looks exactly like a
        target that is filtered.
        """
        encoded = base64.b64encode(payload).decode()
        result = exec_in(
            self.left,
            "python3",
            "-c",
            self._SENDER,
            encoded,
            target,
            str(port),
            str(timeout_s),
            timeout=int(timeout_s) + 30,
        )
        output = result.stdout.strip()
        if not output or output.startswith("ERR:"):
            return None
        return base64.b64decode(output)

    @contextmanager
    def reachability(self) -> Iterator[list[Reachability]]:
        """Sample reachability across the tunnel for the duration of the block.

        The result is appended on exit, so the caller reads it after the block.
        """
        holder: list[Reachability] = []
        probe = (
            "while :; do "
            f"if ping -n -c 1 -W {PROBE_TIMEOUT_S} -q {RIGHT_HOST_IP} >/dev/null 2>&1; "
            "then r=ok; else r=lost; fi; "
            'printf "%s %s\\n" "$(date +%s.%N)" "$r"; '
            f"sleep {PROBE_INTERVAL_S}; "
            "done"
        )
        exec_in(self.left_host, "sh", "-c", f"({probe}) > {PROBE_LOG} 2>&1 &", timeout=30)
        time.sleep(2)  # a baseline of good samples before anything changes
        started = time.monotonic()
        try:
            yield holder
        finally:
            block_s = time.monotonic() - started
            exec_in(self.left_host, "pkill", "-f", "while :;", timeout=30)
            exec_in(self.left_host, "pkill", "-x", "ping", timeout=30)
            time.sleep(0.5)
            log = exec_in(self.left_host, "cat", PROBE_LOG, timeout=30).stdout
            samples = parse_probe(log)
            assert samples, f"the reachability probe recorded nothing:\n{log[-800:]}"
            holder.append(Reachability(samples, block_s))


@contextmanager
def live_pair(
    config: TunnelConfig, *, capture_to: Path | None = None, ike_capture: bool = False
) -> Iterator[LivePair]:
    """Bring up a pair on ``config`` with editable configuration files.

    ``capture_to`` starts a dual capture on the left gateway **before** the tunnel is
    initiated, so the first handshake lands in the outer PCAP. A capture started after
    initiation records ESP with no negotiation to read, which looks healthy and is
    useless to the deterministic lane.

    ``ike_capture`` does the same for the IKE-only capture watch mode reads. It has to
    start first for the same reason and a sharper one: a later rekey is carried in
    CREATE_CHILD_SA, whose SA payload is encrypted, so IKE_SA_INIT is the only chance a
    passive observer gets to read a tunnel's parameters.
    """
    conf_dir = Path(tempfile.mkdtemp(prefix="sentinel-live-"))
    confs: dict[Role, Path] = {"left": conf_dir / "left.conf", "right": conf_dir / "right.conf"}
    for role, path in confs.items():
        path.write_text(render_swanctl_conf(config, role))

    env = {
        "SENTINEL_PSK": secrets.token_hex(24),
        "LEFT_CONF": str(confs["left"]),
        "RIGHT_CONF": str(confs["right"]),
    }
    with compose_project(PAIR_COMPOSE, env=env) as project:

        def cid(service: str) -> str:
            out = compose(PAIR_COMPOSE, project, "ps", "-q", service).stdout.strip()
            assert out, f"no container for service {service}"
            return out

        containers = {name: cid(name) for name in ("left", "right", "left_host", "right_host")}
        pair = LivePair(config, containers, confs)
        with ExitStack() as stack:
            if capture_to is not None:
                capture_to.mkdir(parents=True, exist_ok=True)
                capture = dual_capture_for_pair(
                    containers["left"], LEFT_TRANSIT_IP, LEFT_PROTECTED_IP, capture_to
                )
                stack.enter_context(capture)
                pair.capture = capture
            if ike_capture:
                pair.start_ike_capture()
            started = pair.initiate()
            assert started.returncode == 0, f"tunnel did not establish: {started.stdout[-400:]}"
            yield pair

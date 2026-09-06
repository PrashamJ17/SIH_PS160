"""Execute the zero-downtime sequence on a live pair (build plan Step 8.4).

The unit tests prove the sequence is safe *in the model*. This proves the model
describes strongSwan. It runs the four steps against two real peers while a ping runs
across the tunnel throughout, and asserts the ping loses nothing.

Two controls keep that assertion honest, because "0% packet loss" is exactly what a
ping that measured nothing also reports:

* :class:`TestTheNaiveApproachIsWorse` performs the obvious replacement instead and
  asserts the same measurement *does* see loss. A meter that cannot read non-zero is
  not evidence.
* :func:`test_a_state_with_no_common_proposal_really_does_fail` puts the two ends into
  the state the simulation calls unsafe and shows the negotiation genuinely fails —
  tying the modelled property to an observable outcome rather than an assumption.

One finding from building this is baked into the sequence itself: on strongSwan 5.9.8
an established SA keeps the configuration it was created with, so ``swanctl --rekey``
after a reload renegotiates the *old* proposal and the change silently does nothing.
:class:`TestRekeyDoesNotAdoptNewConfiguration` pins that behaviour, because it is the
reason step 2 initiates a second SA instead of rekeying, and if a future strongSwan
changes it we want to be told rather than to keep carrying the workaround.
"""

from __future__ import annotations

import re
import secrets
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

from ipsec_sentinel.remediate.generators.strongswan import harden
from ipsec_sentinel.remediate.sequence import STEP_COUNT, build_sequence, verify_zero_downtime
from testbed.orchestrate.config_gen import TunnelConfig, render_swanctl_conf
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.dockerctl import compose, compose_project, exec_in

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PAIR_COMPOSE: Final = REPO_ROOT / "testbed" / "compose" / "pair.yml"
LEFT_HOST_IP: Final = "10.1.0.10"
RIGHT_HOST_IP: Final = "10.2.0.10"
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

    def __init__(self, config: TunnelConfig, containers: dict[str, str], confs: dict[str, Path]):
        self.config = config
        self.left = containers["left"]
        self.right = containers["right"]
        self.left_host = containers["left_host"]
        self._confs = confs

    def set_proposals(self, ike: str, esp: str) -> None:
        """Rewrite both ends' configuration files with these proposal lists."""
        for role, path in self._confs.items():
            text = render_swanctl_conf(self.config, role)  # type: ignore[arg-type]
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

    def terminate(self, ike_id: int) -> None:
        exec_in(self.left, "swanctl", "--terminate", "--ike-id", str(ike_id), timeout=120)

    def sas(self, container: str | None = None) -> list[LiveSa]:
        listing = exec_in(container or self.left, "swanctl", "--list-sas", timeout=60).stdout
        return parse_sas(listing)

    def sa_carrying(self, config: TunnelConfig, container: str | None = None) -> LiveSa | None:
        return next((sa for sa in self.sas(container) if sa.carries(config)), None)

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
def live_pair(config: TunnelConfig) -> Iterator[LivePair]:
    """Bring up a pair on ``config`` with editable configuration files."""
    conf_dir = Path(tempfile.mkdtemp(prefix="sentinel-seq-"))
    confs = {"left": conf_dir / "left.conf", "right": conf_dir / "right.conf"}
    for role, path in confs.items():
        path.write_text(render_swanctl_conf(config, role))  # type: ignore[arg-type]

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
        started = pair.initiate()
        assert started.returncode == 0, f"tunnel did not establish: {started.stdout[-400:]}"
        yield pair


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def transition() -> tuple[TunnelConfig, TunnelConfig]:
    """A weak configuration and its hardened form, both IKEv2.

    The proposal is the only thing that changes. An IKE version change is a different
    and larger operation, and mixing it in would leave it unclear which part of the
    sequence a failure belonged to.
    """
    current = anchor("weak")
    target, changes = harden(current)
    assert changes, "the weak anchor should have something to correct"
    assert current.ike_version == target.ike_version == "ikev2"
    assert current.proposal_string() != target.proposal_string()
    return current, target


def both_lists(current: TunnelConfig, target: TunnelConfig) -> tuple[str, str]:
    """Proposal lists offering the target first and the current as a fallback."""
    return (
        f"{target.proposal_string()},{current.proposal_string()}",
        f"{target.esp_proposal_string()},{current.esp_proposal_string()}",
    )


# ---------------------------------------------------------------------------- the run


class TestTheSequenceRunsWithoutLosingAPacket:
    def test_the_full_sequence_holds_the_tunnel_up_throughout(self) -> None:
        """The demo moment: four steps, a live pair, and a ping that loses nothing."""
        current, target = transition()
        steps = build_sequence(current.proposal_string(), target.proposal_string())
        assert len(steps) == STEP_COUNT
        verify_zero_downtime(current.proposal_string(), target.proposal_string())

        with live_pair(current) as pair:
            before = pair.sa_carrying(current)
            assert before is not None, f"expected the weak proposal, saw {pair.sas()}"

            with pair.reachability() as measured:
                # Step 1 — add the target alongside the current on both ends.
                pair.set_proposals(*both_lists(current, target))
                pair.load()
                time.sleep(1)
                assert pair.sa_carrying(current) is not None, (
                    "reloading the configuration disturbed the running SA; step 1 is "
                    "supposed to be inert"
                )

                # Step 2 — establish a second SA on the target, then retire the old.
                assert pair.initiate().returncode == 0
                time.sleep(SETTLE_S)
                migrated = pair.sa_carrying(target)
                assert migrated is not None, (
                    "the new SA did not negotiate the target proposal; step 2 says to "
                    f"stop here rather than continue. SAs: {pair.sas()}"
                )
                stale = pair.sa_carrying(current)
                assert stale is not None and stale.ike_id != migrated.ike_id
                pair.terminate(stale.ike_id)
                time.sleep(SETTLE_S)

                # Step 3 — remove the current proposal from both ends.
                pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
                pair.load()
                time.sleep(1)

                # Step 4 — still established, on the target alone.
                remaining = pair.sas()
                assert len(remaining) == 1, f"expected one SA, saw {remaining}"
                assert remaining[0].carries(target)
                assert pair.sa_carrying(current) is None

            result = measured[0]

        print(f"\nzero-downtime sequence: {result.summary()}")
        assert result.coverage > MIN_PROBE_COVERAGE, (
            f"the probe watched only {result.measured_s:.1f}s of a {result.block_s:.1f}s "
            f"change, so it was not looking during part of it and its verdict says "
            f"nothing about that part: {result.summary()}"
        )
        assert result.lost == 0, f"the sequence dropped traffic: {result.summary()}"
        assert result.longest_outage_s == 0.0, (
            f"the tunnel was unreachable during the change: {result.summary()}"
        )

    def test_both_ends_agree_on_the_result(self) -> None:
        """A change applied to one end only is the failure the sequence exists to avoid."""
        current, target = transition()
        with live_pair(current) as pair:
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)
            migrated = pair.sa_carrying(target)
            assert migrated is not None
            stale = pair.sa_carrying(current)
            assert stale is not None
            pair.terminate(stale.ike_id)
            time.sleep(SETTLE_S)

            for end in (pair.left, pair.right):
                sas = pair.sas(end)
                assert len(sas) == 1, f"{end} sees {sas}"
                assert sas[0].carries(target), f"{end} did not move to the target: {sas[0]}"
                assert sas[0].esp_algorithms, f"{end} has no child SA installed"


class TestTheNaiveApproachIsWorse:
    """The negative control. Without it, "0% loss" could mean the meter is broken."""

    def test_replacing_the_proposal_outright_loses_packets(self) -> None:
        current, target = transition()
        with live_pair(current) as pair:
            with pair.reachability() as measured:
                time.sleep(2)
                # No add-alongside step: replace on both ends, then force the new
                # configuration to take effect the only way that remains.
                pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
                pair.load()
                exec_in(pair.left, "swanctl", "--terminate", "--ike", "net-net", timeout=120)
                time.sleep(SETTLE_S)
                assert pair.initiate().returncode == 0
                time.sleep(SETTLE_S)
                assert pair.sa_carrying(target) is not None
            result = measured[0]

        print(f"\nnaive replacement: {result.summary()}")
        assert result.coverage > MIN_PROBE_COVERAGE, result.summary()
        assert result.longest_outage_s >= MIN_CONTROL_OUTAGE_S, (
            f"the naive replacement caused no sustained outage, so this measurement "
            f"has not been shown to detect one at all; without that the zero-loss "
            f"result above proves nothing: {result.summary()}"
        )
        assert result.lost > 0, result.summary()


def test_a_state_with_no_common_proposal_really_does_fail() -> None:
    """The modelled unsafe state, reproduced on real peers.

    ``simulate`` calls a state unsafe when the two ends share no proposal. This puts
    them in exactly that state and shows the negotiation fails, which is what ties the
    model to something observable.
    """
    current, target = transition()
    with live_pair(current) as pair:
        exec_in(pair.left, "swanctl", "--terminate", "--ike", "net-net", timeout=120)
        time.sleep(1)
        # The local end offers only the target; the peer still offers only the current.
        pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
        pair.load(both_ends=False)
        attempt = pair.initiate()

        assert attempt.returncode != 0, (
            "the two ends share no proposal, so this must not establish; it did"
        )
        assert "NO_PROPOSAL_CHOSEN" in attempt.stdout + attempt.stderr, (
            f"expected a proposal mismatch, got: {(attempt.stdout + attempt.stderr)[-500:]}"
        )


class TestRekeyDoesNotAdoptNewConfiguration:
    """Why step 2 initiates instead of rekeying.

    Pinned as a test rather than a comment: it is a behavioural claim about strongSwan
    that the sequence depends on, and if a later release changes it we should find out
    from a failing test rather than by keeping a workaround forever.
    """

    def test_a_rekey_after_a_reload_renegotiates_the_old_proposal(self) -> None:
        current, target = transition()
        with live_pair(current) as pair:
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            time.sleep(1)
            for kind in ("ike", "child"):
                result = exec_in(
                    pair.left, "swanctl", "--rekey", f"--{kind}", "net-net", timeout=120
                )
                assert result.returncode == 0, result.stderr[:300]
                time.sleep(SETTLE_S)

            assert pair.sa_carrying(target) is None, (
                "strongSwan now adopts reloaded proposals on rekey — the sequence can "
                "be simplified to a rekey, and this test should be replaced"
            )
            assert pair.sa_carrying(current) is not None

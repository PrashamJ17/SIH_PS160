"""Continuous watch: notice when a tunnel gets weaker.

An assessment is a photograph. This is the film, and it exists because the failure it
catches is not "someone deployed a bad tunnel" — an audit finds those — but "someone
changed a good tunnel back". A gateway is replaced under warranty, a vendor's default
configuration is restored during an out-of-hours fix, a template is rolled back. The
tunnel comes up, traffic flows, nobody is paged, and the estate is quietly weaker than
the last report said it was.

**Drift is a comparison against this tunnel's own past, not against a baseline.** A
tunnel that was always mediocre is a finding the assessment already made. A tunnel that
*was* strong and is now mediocre is news, and it is news whether or not the new state
breaches the selected policy — the direction of travel is the signal.

**A tunnel's parameters are only readable at IKE_SA_INIT.** A rekey is carried in
CREATE_CHILD_SA, whose SA payload sits inside the encrypted SK payload, so a passive
observer cannot read what a rekey agreed — only that one happened.

That limit is narrower than it sounds, for a reason measured in Step 8.4: an IKE SA keeps
the configuration it was created with, and a rekey renegotiates the *old* parameters. A
configuration change therefore only takes effect when a new IKE SA is built, and building
one is an IKE_SA_INIT in the clear. The moment the estate actually becomes weaker is the
moment it becomes visible. A tunnel that has not re-established is still running the
parameters last seen, so there is nothing yet to miss.

Three things follow, and all three are handled rather than left as caveats:

* **A restarted watcher must not forget.** Without its history the next sighting reads as
  a first sighting and no drift is reported, which is the one moment an operator most
  needs one. :meth:`DriftDetector.save` and :meth:`DriftDetector.load` persist it.
* **A watcher started fresh has no past to compare against.** It can be seeded from a
  previous assessment with :meth:`DriftDetector.seed_from_report`, so the comparison is
  against the last audit rather than against nothing.
* **A tunnel that has not been seen negotiating is unverified, not verified.**
  :meth:`DriftDetector.stale` names those tunnels and how long it has been, so a quiet
  alert log is distinguishable from a quiet network.

One residual limit stays a limit and is recorded in ``docs/LIMITATIONS.md``: RFC 7296
permits a rekey to renegotiate the SA payload, so an implementation that re-reads its
configuration at rekey time *could* change parameters where this tool cannot see it.
strongSwan does not — that was measured, not assumed — but not every stack is strongSwan.

Two things this deliberately does not do. It does not alert on a tunnel it is seeing for
the first time: with no past there is no drift, and treating a first sighting as a change
would fill an operator's inbox on every restart until they stopped reading it. And it
never reports a *strengthening* as drift, though it records one, because an alert that
fires on good news is an alert people learn to close.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.assess.scoring import score_tunnel
from ipsec_sentinel.collect import DeviceState
from ipsec_sentinel.logging import get_logger
from ipsec_sentinel.models import IKEExchange, Severity
from ipsec_sentinel.parser.constants import dh_security_bits
from ipsec_sentinel.parser.correlate import Tunnel, endpoint_pair, group_negotiations
from ipsec_sentinel.parser.pcap import extract_ike_exchanges
from ipsec_sentinel.remediate.config import TunnelConfig
from ipsec_sentinel.remediate.generators.strongswan import DH_GROUP_NUMBERS
from ipsec_sentinel.remediate.observed import config_from_exchange

# IKE only. The outer capture is mostly ESP, and a watcher that re-reads a growing file
# would spend all its time skipping payloads it cannot read anyway.
IKE_BPF: Final = "udp port 500 or udp port 4500"
DEFAULT_POLL_S: Final = 2.0
# Bumped when the saved shape changes. A file this build cannot read is ignored, not
# migrated: losing the history costs one missed comparison, and guessing at an older
# layout could restore a *wrong* past and then report drift that never happened.
STATE_VERSION: Final = 1

logger = get_logger(__name__)

# Relative strength of the ciphers the reconstruction can name. Only the ordering
# matters, and only for deciding whether a change went the wrong way.
CIPHER_RANK: Final[dict[str, int]] = {
    "null": 0,
    "des": 1,
    "3des": 2,
    "rc5": 2,
    "idea": 2,
    "blowfish": 2,
    "cast": 2,
    "camellia": 4,
    "aes128": 4,
    "aes192": 5,
    "aes256": 6,
    "aes128gcm16": 7,
    "aes256gcm16": 8,
}
INTEGRITY_RANK: Final[dict[str, int]] = {
    "md5": 1,
    "sha1": 2,
    "sha256": 4,
    "sha384": 5,
    "sha512": 6,
}
PRF_RANK: Final[dict[str, int]] = {
    "prfmd5": 1,
    "prfsha1": 2,
    "prfsha256": 4,
    "prfsha384": 5,
    "prfsha512": 6,
}


class ExchangeSource(Protocol):
    """Somewhere IKE negotiations arrive from."""

    def poll(self) -> list[IKEExchange]:
        """Every exchange seen since the last call. Empty when nothing new arrived."""

    def close(self) -> None: ...


def _dh_bits(name: str | None) -> int | None:
    number = DH_GROUP_NUMBERS.get(name or "")
    return dh_security_bits(number) if number is not None else None


@dataclass(frozen=True)
class Weakening:
    """One parameter that moved the wrong way."""

    parameter: str
    previous: str
    current: str
    detail: str

    def describe(self) -> str:
        return f"{self.parameter}: {self.previous} -> {self.current} ({self.detail})"


def compare(previous: TunnelConfig, current: TunnelConfig) -> list[Weakening]:
    """Every way ``current`` is weaker than ``previous``.

    Compared parameter by parameter rather than by score alone. A score can stay level
    while something specific gets worse — a stronger cipher paired with a weaker group,
    say — and an operator asked to act needs to be told which setting moved.
    """
    weakenings: list[Weakening] = []

    if previous.ike_version == "ikev2" and current.ike_version == "ikev1":
        weakenings.append(
            Weakening(
                "ike_version",
                "ikev2",
                "ikev1",
                "IKEv1 is deprecated by RFC 9395 and has no protection against the "
                "offline attacks IKEv2 closed",
            )
        )
    if current.aggressive and not previous.aggressive:
        weakenings.append(
            Weakening(
                "aggressive_mode",
                "off",
                "on",
                "aggressive mode sends the authentication hash before encryption begins, "
                "so a captured handshake is enough to attack a pre-shared key offline",
            )
        )

    before, after = CIPHER_RANK.get(previous.encryption), CIPHER_RANK.get(current.encryption)
    if before is not None and after is not None and after < before:
        weakenings.append(
            Weakening("encryption", previous.encryption, current.encryption, "weaker cipher")
        )

    before, after = (
        INTEGRITY_RANK.get(previous.integrity or ""),
        INTEGRITY_RANK.get(current.integrity or ""),
    )
    if before is not None and after is not None and after < before:
        weakenings.append(
            Weakening(
                "integrity", previous.integrity or "-", current.integrity or "-", "weaker hash"
            )
        )

    before, after = PRF_RANK.get(previous.prf), PRF_RANK.get(current.prf)
    if before is not None and after is not None and after < before:
        weakenings.append(Weakening("prf", previous.prf, current.prf, "weaker PRF"))

    # Compared on security bits, not parameter size: 256-bit ECP is stronger than
    # 2048-bit MODP, and the printed numbers say the opposite.
    before_bits, after_bits = _dh_bits(previous.dh_group), _dh_bits(current.dh_group)
    if before_bits is not None and after_bits is not None and after_bits < before_bits:
        weakenings.append(
            Weakening(
                "dh_group",
                previous.dh_group,
                current.dh_group,
                f"{after_bits}-bit strength, down from {before_bits}",
            )
        )

    if previous.pfs and not current.pfs:
        weakenings.append(
            Weakening(
                "pfs",
                "enabled",
                "disabled",
                "one compromised key now decrypts every child SA derived from it",
            )
        )
    return weakenings


@dataclass(frozen=True)
class Sighting:
    """What a tunnel was seen negotiating, once."""

    endpoints: tuple[str, str]
    config: TunnelConfig
    score: int | None
    """The assessed score, or ``None`` when it could not be assessed.

    A sighting read from a device's own state has no negotiation for the rule engine to
    evaluate, and running the rules against an empty tunnel returns no findings and a
    perfect score. Reporting that would be a lie in the most misleading direction — the
    tunnel would appear to score 100 precisely because nothing was checked. The drift
    signal is the parameter comparison, which is exact either way.
    """

    grade: str | None
    exchange: IKEExchange | None
    """The negotiation this was read from, or ``None`` when restored from saved state.

    Kept nullable rather than fabricated: a sighting recovered from a state file or a
    previous report is a real record of what the tunnel was, and inventing a wire
    message to go with it would make a reconstruction indistinguishable from an
    observation.
    """

    seen_at: datetime

    @property
    def suite(self) -> str:
        return self.config.proposal_string()


@dataclass(frozen=True)
class StaleTunnel:
    """A tunnel whose current parameters have not been observed recently."""

    endpoints: tuple[str, str]
    last_seen: datetime
    silent_for_s: float
    suite: str

    def describe(self) -> str:
        hours = self.silent_for_s / 3600
        return (
            f"{self.endpoints[0]} <-> {self.endpoints[1]}: last seen negotiating "
            f"{hours:.1f}h ago as {self.suite}. Its parameters since then are "
            f"unverified, not confirmed unchanged."
        )


@dataclass(frozen=True)
class DriftAlert:
    """A tunnel is weaker than the last time it was seen."""

    endpoints: tuple[str, str]
    previous: Sighting
    current: Sighting
    weakenings: tuple[Weakening, ...]
    detected_at: datetime

    @property
    def severity(self) -> Severity:
        """Any weakening is at least HIGH; a score collapse is CRITICAL.

        A weakening is an active change made by someone with access, not a
        configuration that drifted from a standard on its own, and it deserves to be
        read that way.
        """
        drop = self.score_drop
        if drop is not None and drop >= CRITICAL_SCORE_DROP:
            return Severity.CRITICAL
        # With no score to compare — a device-state sighting — severity falls back to
        # what changed. A cipher, a protocol version or aggressive mode moving the wrong
        # way is a different order of problem from a PRF, and the alert should say so
        # rather than defaulting everything to the same level.
        if any(w.parameter in CRITICAL_PARAMETERS for w in self.weakenings):
            return Severity.CRITICAL
        return Severity.HIGH

    @property
    def score_drop(self) -> int | None:
        """How far the score fell, or ``None`` if either end was not assessed."""
        if self.previous.score is None or self.current.score is None:
            return None
        return self.previous.score - self.current.score

    def summary(self) -> str:
        scored = (
            f" (score {self.previous.score} -> {self.current.score})"
            if self.previous.score is not None and self.current.score is not None
            else " (not scored: read from device state, which carries no negotiation)"
        )
        return (
            f"{self.endpoints[0]} <-> {self.endpoints[1]} weakened: "
            f"{self.previous.suite} -> {self.current.suite}{scored}; "
            + "; ".join(w.describe() for w in self.weakenings)
        )


CRITICAL_SCORE_DROP: Final = 30

# Weakenings that are critical on their own, used when no score comparison is available.
CRITICAL_PARAMETERS: Final[frozenset[str]] = frozenset(
    {"encryption", "ike_version", "aggressive_mode", "pfs"}
)


class DriftDetector:
    """Remembers what each tunnel was last seen negotiating.

    Keyed on the endpoint pair rather than the tunnel id: a tunnel id is derived from
    the negotiation, so it changes when the configuration does — which is exactly the
    moment the comparison must still find the previous state.
    """

    def __init__(
        self, baseline: str = DEFAULT_BASELINE, registry: RuleRegistry | None = None
    ) -> None:
        self.baseline = baseline
        self.registry = registry or default_registry()
        self._last: dict[tuple[str, str], Sighting] = {}
        self._lock = threading.Lock()

    def resolve_baseline(self) -> None:
        """Fail now if the baseline name is wrong, not on the first negotiation.

        A watcher that starts, prints "watching", and then raises twenty minutes later
        when something finally shows up is worse than one that refuses immediately.
        """
        self.registry.resolve(self.baseline)

    def sighting(self, exchange: IKEExchange) -> Sighting | None:
        """Turn an exchange into a comparable state, or ``None`` if it cannot be read."""
        recovered = config_from_exchange(exchange)
        if not recovered.ok or recovered.config is None:
            return None
        endpoints = endpoint_pair(exchange.src_ip, exchange.dst_ip)
        tunnel = Tunnel(
            tunnel_id=f"{endpoints[0]}-{endpoints[1]}",
            endpoints=endpoints,
            ike=exchange,
            negotiation=group_negotiations([exchange])[0],
        )
        findings = self.registry.run(tunnel, self.baseline).findings
        score, grade = score_tunnel(findings)
        return Sighting(
            endpoints=endpoints,
            config=recovered.config,
            score=score,
            grade=grade,
            exchange=exchange,
            seen_at=exchange.timestamp,
        )

    def observe_state(self, state: DeviceState) -> DriftAlert | None:
        """Record what a device says about itself, and report drift if it got weaker.

        This is the answer to the rekey blind spot rather than a workaround for it. The
        wire only reveals parameters at IKE_SA_INIT; a device's own state reveals what is
        installed *right now*, whether or not anyone was listening when it was
        negotiated. Where state is available there is no blind spot left to mitigate.

        Provenance is kept: a sighting from state carries no ``exchange``, so nothing
        downstream can mistake "the device told us" for "we saw it on the wire". The two
        are both parsed facts and they are not the same evidence — a capture can be
        re-read by anyone, while a device's self-report is only as good as the device.
        """
        from ipsec_sentinel.collect import config_from_state

        endpoints = state.endpoints
        config = config_from_state(state)
        if endpoints is None or not isinstance(config, TunnelConfig):
            return None

        # Deliberately not scored. The rule engine assesses a negotiation, and running
        # it against a tunnel that has none returns no findings and therefore a perfect
        # score — a tunnel would appear to score 100 exactly because nothing was checked.
        current = Sighting(
            endpoints=endpoints,
            config=config,
            score=None,
            grade=None,
            exchange=None,
            seen_at=state.collected_at,
        )
        return self._record(current)

    def observe(self, exchange: IKEExchange) -> DriftAlert | None:
        """Record a negotiation and report drift if the tunnel got weaker."""
        current = self.sighting(exchange)
        if current is None:
            return None
        return self._record(current)

    def _record(self, current: Sighting) -> DriftAlert | None:
        """Store a sighting and compare it against the tunnel's own past.

        Shared by the wire and device-state paths so the two cannot diverge on what
        counts as drift — the comparison is the product's judgement and belongs in one
        place, whatever supplied the observation.
        """
        with self._lock:
            previous = self._last.get(current.endpoints)
            self._last[current.endpoints] = current
        if previous is None:
            # First sighting. With no past there is no drift, and alerting here would
            # fire on every tunnel at every restart until nobody read the alerts.
            return None
        weakenings = compare(previous.config, current.config)
        if not weakenings:
            return None
        return DriftAlert(
            endpoints=current.endpoints,
            previous=previous,
            current=current,
            weakenings=tuple(weakenings),
            detected_at=datetime.now(UTC),
        )

    def known(self) -> dict[tuple[str, str], Sighting]:
        with self._lock:
            return dict(self._last)

    def stale(self, older_than_s: float, now: datetime | None = None) -> list[StaleTunnel]:
        """Tunnels not seen negotiating recently, so their parameters are unverified.

        The honest complement to an empty alert log. Silence from a tunnel is not
        evidence that it is still configured the way it was — it is an absence of
        evidence, and the two look identical unless something says which this is.
        """
        moment = now or datetime.now(UTC)
        return sorted(
            (
                StaleTunnel(
                    endpoints=sighting.endpoints,
                    last_seen=sighting.seen_at,
                    silent_for_s=(moment - sighting.seen_at).total_seconds(),
                    suite=sighting.suite,
                )
                for sighting in self.known().values()
                if (moment - sighting.seen_at).total_seconds() > older_than_s
            ),
            key=lambda stale: -stale.silent_for_s,
        )

    def save(self, path: Path) -> Path:
        """Write what each tunnel was last seen negotiating.

        A watcher that restarts and forgets treats the next sighting as a first
        sighting, and reports no drift — at exactly the moment an operator most needs
        one. Written atomically so a kill mid-write leaves the previous state rather
        than a truncated file.
        """
        payload = {
            "version": STATE_VERSION,
            "saved_at": datetime.now(UTC).isoformat(),
            "baseline": self.baseline,
            "tunnels": [
                {
                    "endpoints": list(sighting.endpoints),
                    "seen_at": sighting.seen_at.isoformat(),
                    "score": sighting.score,
                    "grade": sighting.grade,
                    "config": asdict(sighting.config),
                }
                for sighting in self.known().values()
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
        return path

    def load(self, path: Path) -> int:
        """Restore saved state. Returns how many tunnels were remembered.

        A state file this build cannot read is ignored with a warning rather than
        treated as an error: losing the history costs one missed comparison, and
        refusing to start costs every one after it.
        """
        if not path.exists():
            return 0
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("version") != STATE_VERSION:
                logger.warning(
                    "watch_state_version_mismatch",
                    extra={"expected": STATE_VERSION, "found": payload.get("version")},
                )
                return 0
            restored = {}
            for entry in payload["tunnels"]:
                config = TunnelConfig(**entry["config"])
                endpoints = endpoint_pair(*entry["endpoints"])
                restored[endpoints] = Sighting(
                    endpoints=endpoints,
                    config=config,
                    score=None if entry["score"] is None else int(entry["score"]),
                    grade=None if entry["grade"] is None else str(entry["grade"]),
                    exchange=None,
                    seen_at=datetime.fromisoformat(entry["seen_at"]),
                )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("watch_state_unreadable", extra={"path": str(path), "error": str(exc)})
            return 0
        with self._lock:
            self._last.update(restored)
        return len(restored)

    def seed_from_capture(self, pcap: Path) -> int:
        """Take a previous assessment's capture as each tunnel's past.

        So a watcher started today compares against the last audit rather than against
        nothing — the gap that would otherwise let a change made *before* the watcher
        started pass as a first sighting.

        Seeded from the capture and not from the JSON report on purpose. A report records
        the negotiated suite as a display string, and parsing that back into a proposal
        would be a round-trip that can quietly get one transform wrong. The result would
        not be a missing baseline but a **wrong** one, and the watcher would then report
        drift that never happened — which is worse than not seeding at all.
        """
        seeded = 0
        for exchange in extract_ike_exchanges(pcap):
            sighting = self.sighting(exchange)
            if sighting is None:
                continue
            with self._lock:
                previous = self._last.get(sighting.endpoints)
                # Keep the most recent negotiation in the capture, which is the state
                # the tunnel was actually left in.
                if previous is None or sighting.seen_at >= previous.seen_at:
                    self._last[sighting.endpoints] = sighting
                    seeded += 1
        return seeded


class PcapPollSource:
    """Poll a growing capture file and yield negotiations not seen before.

    The file is re-read from the start each time. That is wasteful in principle and
    free in practice: the capture is filtered to IKE, which is a handful of packets per
    tunnel per rekey interval, and the alternative — tracking a byte offset into a file
    another process is appending to — is a source of subtle bugs for no measurable gain.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seen: set[tuple[str, str, str]] = set()

    def poll(self) -> list[IKEExchange]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return []
        try:
            exchanges = extract_ike_exchanges(self.path)
        except (ValueError, OSError):
            # A file being written to can be read mid-packet. The next poll gets it.
            return []
        fresh: list[IKEExchange] = []
        for exchange in exchanges:
            key = (exchange.initiator_spi, exchange.responder_spi, exchange.timestamp.isoformat())
            if key not in self._seen:
                self._seen.add(key)
                fresh.append(exchange)
        return fresh

    def close(self) -> None:
        return None


class LiveInterfaceSource:
    """Capture IKE from a local interface with tcpdump, and read what arrives.

    A subprocess rather than a raw socket: tcpdump drops privileges, has been correct
    for decades, and means this project does not need to run as root in its own process
    to watch an interface.
    """

    def __init__(self, interface: str, bpf: str = IKE_BPF, directory: Path | None = None) -> None:
        self.interface = interface
        target = directory or Path(tempfile.mkdtemp(prefix="sentinel-watch-"))
        target.mkdir(parents=True, exist_ok=True)
        self.path = target / f"watch-{interface}.pcap"
        self._process = subprocess.Popen(
            # -U flushes each packet, so the watcher sees a negotiation seconds after it
            # happens rather than when a 64 kB buffer fills.
            ["tcpdump", "-i", interface, "-U", "-w", str(self.path), bpf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._reader = PcapPollSource(self.path)

    def poll(self) -> list[IKEExchange]:
        if self._process.poll() is not None:
            stderr = self._process.stderr.read().decode() if self._process.stderr else ""
            raise RuntimeError(
                f"tcpdump exited while watching {self.interface}: {stderr.strip()[:300]}"
            )
        return self._reader.poll()

    def close(self) -> None:
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()


@dataclass
class WatchState:
    """What a watch has seen so far."""

    alerts: list[DriftAlert] = field(default_factory=list)
    exchanges: int = 0
    polls: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def watch(
    source: ExchangeSource,
    *,
    on_alert: Callable[[DriftAlert], None] | None = None,
    detector: DriftDetector | None = None,
    poll_s: float = DEFAULT_POLL_S,
    until: float | None = None,
    state: WatchState | None = None,
) -> Iterator[DriftAlert]:
    """Watch a source and yield drift alerts as they are detected.

    A generator rather than a callback loop so a caller can stop simply by not asking
    for the next alert, and so a test can bound it with a deadline.
    """
    tracker = detector or DriftDetector()
    watched = state or WatchState()
    deadline = None if until is None else time.monotonic() + until

    while deadline is None or time.monotonic() < deadline:
        watched.polls += 1
        for exchange in source.poll():
            watched.exchanges += 1
            alert = tracker.observe(exchange)
            if alert is not None:
                watched.alerts.append(alert)
                if on_alert is not None:
                    on_alert(alert)
                yield alert
        time.sleep(poll_s)


def alerts_as_syslog(alerts: Sequence[DriftAlert], **kwargs: object) -> list[str]:
    """Render drift alerts for a SIEM, reusing the Step 9.7 formatters.

    A drift alert is a deterministic finding: the comparison is arithmetic over two
    parsed negotiations, with no model anywhere near it, so it belongs in Section A and
    carries no confidence.
    """
    from ipsec_sentinel.assess.inventory import Inventory
    from ipsec_sentinel.models import Finding
    from ipsec_sentinel.report.build import build_report
    from ipsec_sentinel.report.siem import to_syslog

    report = build_report([], Inventory(), DEFAULT_BASELINE, source="watch")
    lines = []
    for alert in alerts:
        finding = Finding(
            rule_id="DRIFT-01",
            title="Tunnel configuration weakened since it was last seen",
            severity=alert.severity,
            evidence=alert.summary(),
            standard_ref="n/a — comparison against this tunnel's own previous state",
            attack_technique="T1689",
            remediation_hint=(
                "Find out who changed this tunnel and why. A weakening is an active "
                "change by someone with access, not configuration decay."
            ),
            tunnel_id=f"{alert.endpoints[0]}-{alert.endpoints[1]}",
        )
        lines.append(to_syslog(finding, report, **kwargs))  # type: ignore[arg-type]
    return lines

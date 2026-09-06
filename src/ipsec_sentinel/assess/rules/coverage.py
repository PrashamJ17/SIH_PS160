"""Coverage and disclosure rules: ESP-01, ESP-02 and OPS-01.

These three report on what the assessment could *not* establish, and on what the
gateway told the network about itself. Neither is a cryptographic weakness, and both
matter.

An orphan tunnel — ESP with no negotiation in the capture — is the most dangerous entry
in an inventory precisely because nothing can be said about its cryptography. It is
carrying traffic, it was configured by someone at some point, and the capture window
never contained a handshake to read. A report that lists it silently alongside fully
assessed tunnels invites the reader to assume it was checked. It was not.

A negotiation with no traffic behind it is the mirror case, and it is usually the more
interesting of the two operationally: a tunnel that negotiates and then carries nothing
is either failing repeatedly or has outlived whatever it was built for.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE
from ipsec_sentinel.models import Finding, Severity
from ipsec_sentinel.parser.correlate import Tunnel


@dataclass(frozen=True)
class CoverageRule:
    """A rule about assessment coverage or information disclosure."""

    id: str
    title: str
    severity: Severity
    standard_ref: str
    remediation_hint: str
    attack_technique: str | None = None
    baselines: list[str] = field(default_factory=lambda: [DEFAULT_BASELINE])

    def evaluate(self, tunnel: Tunnel) -> Finding | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _finding(self, evidence: str) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            evidence=evidence,
            standard_ref=self.standard_ref,
            attack_technique=self.attack_technique,
            remediation_hint=self.remediation_hint,
        )


@dataclass(frozen=True)
class UnassessableTunnel(CoverageRule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if not tunnel.is_orphan or not tunnel.flows:
            return None
        spis = ", ".join(sorted({flow.spi for flow in tunnel.flows}))
        return self._finding(
            f"{tunnel.packet_count} ESP packets ({tunnel.byte_count} bytes) on SPI(s) "
            f"{spis} between {tunnel.endpoints[0]} and {tunnel.endpoints[1]}, with no "
            f"IKE negotiation in the capture. The cryptographic parameters of this "
            f"tunnel are unknown — it is not assessed, and it is not clean; it is "
            f"unexamined"
        )


@dataclass(frozen=True)
class NegotiationWithoutTraffic(CoverageRule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if not tunnel.negotiation_only:
            return None
        assert tunnel.ike is not None
        return self._finding(
            f"an IKE negotiation ({tunnel.ike.version} {tunnel.ike.exchange_type}) was "
            f"observed between {tunnel.endpoints[0]} and {tunnel.endpoints[1]} with no "
            f"ESP traffic behind it. The tunnel either failed to establish, or is "
            f"established and idle"
        )


@dataclass(frozen=True)
class ImplementationDisclosure(CoverageRule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.negotiation is None:
            return None
        printable: list[str] = []
        for message in tunnel.negotiation.messages:
            for vendor_id in message.vendor_ids:
                try:
                    decoded = bytes.fromhex(vendor_id).decode("ascii")
                except (ValueError, UnicodeDecodeError):
                    continue
                # Only cleartext names disclose anything a reader can act on. An
                # opaque hash fingerprints an implementation too, but reporting every
                # vendor ID would bury the ones that literally spell out a version.
                if decoded.isprintable() and any(c.isalpha() for c in decoded):
                    printable.append(decoded.strip())
        if not printable:
            return None
        unique = sorted(set(printable))
        return self._finding(
            f"the peer advertised its implementation in cleartext vendor ID payloads: "
            f"{', '.join(repr(v) for v in unique)}. Anyone capturing the handshake "
            f"learns which software and version to look up advisories for, before "
            f"sending a single packet to the gateway"
        )


ESP_01 = UnassessableTunnel(
    id="ESP-01",
    title="ESP traffic with no observed negotiation (unassessable tunnel)",
    severity=Severity.MEDIUM,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.4 (inventory and monitoring)",
    remediation_hint=(
        "Capture across a rekey, or supply this tunnel's configuration, so its "
        "cryptography can be assessed. A long-lived tunnel that never renegotiates "
        "within a capture window is also the one most likely to be running settings "
        "chosen years ago."
    ),
)

ESP_02 = NegotiationWithoutTraffic(
    id="ESP-02",
    title="IKE negotiation with no protected traffic",
    severity=Severity.LOW,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.4 (inventory and monitoring)",
    remediation_hint=(
        "Check whether this tunnel is failing to establish or is simply idle. A tunnel "
        "that repeatedly negotiates and carries nothing is usually a misconfigured "
        "traffic selector; one that is idle may no longer be needed."
    ),
)

OPS_01 = ImplementationDisclosure(
    id="OPS-01",
    title="Implementation and version disclosed in vendor ID",
    severity=Severity.LOW,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1",
    attack_technique="T1592.002",
    remediation_hint=(
        "Suppress or genericise the vendor ID payload if the implementation allows it. "
        "This is defence in depth rather than a vulnerability — but it hands an "
        "attacker the exact version to search advisories for, at zero cost and with no "
        "packet sent to the gateway."
    ),
)

COVERAGE_RULES: list[CoverageRule] = [ESP_01, ESP_02, OPS_01]

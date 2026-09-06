"""SIEM output: CEF, LEEF, and an RFC 5424 syslog emitter.

Three formats because the collector on the other end is not this project's choice.
ArcSight reads CEF, QRadar reads LEEF, and almost everything reads syslog. All three are
built from the same findings, so a site that switches collectors does not switch what it
is told.

**Formatting and sending are separate on purpose.** :func:`to_cef`, :func:`to_leef` and
:func:`to_syslog` are pure functions over a report — no socket, no clock, no environment
— which is what makes them testable against the format specifications. Only
:class:`SyslogEmitter` opens a socket, and nothing constructs one unless a caller
explicitly asks: this tool's central claim is that it observes and does not act, and an
analysis run that quietly dials out to a collector would undermine that even though the
payload is innocuous. Step 11.3 asserts the same property from the other direction.

**Escaping is where these formats go wrong.** A finding's evidence contains algorithm
names, peer identities and free text read off the wire, and every one of the delimiters
these formats use — ``|``, ``=``, tab, newline — can appear in it. An unescaped pipe
does not corrupt one field; it shifts every field after it, so the collector reads the
severity out of the message body. Each format's escaping is implemented to its own
specification and tested with a payload containing all of them at once.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Final

from ipsec_sentinel.models import Finding, Severity
from ipsec_sentinel.report.models import Report

VENDOR: Final = "IPsecSentinel"
PRODUCT: Final = "IPsec Sentinel"

# RFC 5424 section 6. A receiver must accept 480 octets and should accept 2048; 1024 is
# the conservative middle that every collector in practice handles.
MAX_SYSLOG_OCTETS: Final = 1024
TRUNCATION_MARKER: Final = "...[truncated]"

# IANA reserved 32473 for documentation and private use in examples (RFC 5612), which is
# exactly what a structured-data ID needs when the project has no enterprise number.
ENTERPRISE_NUMBER: Final = 32473
SD_ID: Final = f"ipsecSentinel@{ENTERPRISE_NUMBER}"

# RFC 5424 section 6.2.1. local0 is the conventional facility for application security
# events; a site that wants another one passes it in.
FACILITY_LOCAL0: Final = 16
SYSLOG_VERSION: Final = 1
NIL: Final = "-"
BOM: Final = "\ufeff"


class SyslogSeverity(IntEnum):
    """RFC 5424 section 6.2.1 severity codes."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


SYSLOG_SEVERITY: Final[dict[Severity, SyslogSeverity]] = {
    Severity.CRITICAL: SyslogSeverity.CRITICAL,
    Severity.HIGH: SyslogSeverity.ERROR,
    Severity.MEDIUM: SyslogSeverity.WARNING,
    Severity.LOW: SyslogSeverity.NOTICE,
    Severity.INFO: SyslogSeverity.INFORMATIONAL,
}

# CEF severity is 0-10. Mapped so the five levels spread across the range rather than
# bunching at the top, which is what makes a collector's own thresholds usable.
CEF_SEVERITY: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 8,
    Severity.MEDIUM: 5,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


def priority(severity: Severity, facility: int = FACILITY_LOCAL0) -> int:
    """PRI = facility * 8 + severity, per RFC 5424 section 6.2.1."""
    return facility * 8 + SYSLOG_SEVERITY[severity]


# --------------------------------------------------------------------------------- CEF


def cef_escape_header(value: str) -> str:
    """Escape a CEF header field: backslash first, then the pipe delimiter.

    Order matters. Escaping the pipe first would then have its own backslash escaped by
    the second pass, producing ``\\\\|`` — a literal backslash followed by an
    unescaped delimiter, which is the bug the escaping exists to prevent.
    """
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def cef_escape_extension(value: str) -> str:
    """Escape a CEF extension value: backslash, then ``=``, then newlines."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def _extensions(pairs: Sequence[tuple[str, str | None]]) -> str:
    return " ".join(
        f"{key}={cef_escape_extension(value)}" for key, value in pairs if value is not None
    )


def to_cef(finding: Finding, report: Report, cef_version: int = 0) -> str:
    """One finding as a CEF event.

    ``CEF:Version|Vendor|Product|ProductVersion|SignatureID|Name|Severity|Extension``
    """
    header = "|".join(
        [
            f"CEF:{cef_version}",
            cef_escape_header(VENDOR),
            cef_escape_header(PRODUCT),
            cef_escape_header(report.metadata.tool_version),
            cef_escape_header(finding.rule_id),
            cef_escape_header(finding.title),
            str(CEF_SEVERITY[finding.severity]),
        ]
    )
    extension = _extensions(
        [
            ("cs1Label", "tunnelId"),
            ("cs1", finding.tunnel_id),
            ("cs2Label", "standard"),
            ("cs2", finding.standard_ref),
            ("cs3Label", "attackTechnique"),
            ("cs3", finding.attack_technique),
            ("cs4Label", "assurance"),
            # The Section A / Section B distinction has to survive into the SIEM, or an
            # analyst triaging an alert cannot tell a parsed fact from an estimate.
            ("cs4", "verified" if finding.is_deterministic else "inferred"),
            (
                "cn1Label",
                None if finding.is_deterministic else "confidence",
            ),
            (
                "cn1",
                None if finding.confidence is None else f"{finding.confidence.value:.4f}",
            ),
            ("msg", finding.evidence),
            ("reason", finding.remediation_hint),
            ("externalId", report.metadata.source),
        ]
    )
    return f"{header}|{extension}"


# -------------------------------------------------------------------------------- LEEF


def leef_escape(value: str) -> str:
    """Escape a LEEF attribute value.

    Attributes are tab-delimited, so a tab inside a value ends the field early and
    every attribute after it is misread.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
        .replace("=", "\\=")
    )


def to_leef(finding: Finding, report: Report) -> str:
    """One finding as a LEEF 1.0 event, tab-delimited.

    ``LEEF:1.0|Vendor|Product|Version|EventID|Attributes``
    """
    header = "|".join(
        [
            "LEEF:1.0",
            cef_escape_header(VENDOR),
            cef_escape_header(PRODUCT),
            cef_escape_header(report.metadata.tool_version),
            cef_escape_header(finding.rule_id),
        ]
    )
    pairs: list[tuple[str, str | None]] = [
        ("sev", str(CEF_SEVERITY[finding.severity])),
        ("cat", finding.title),
        ("tunnelId", finding.tunnel_id),
        ("standard", finding.standard_ref),
        ("attackTechnique", finding.attack_technique),
        ("assurance", "verified" if finding.is_deterministic else "inferred"),
        ("confidence", None if finding.confidence is None else f"{finding.confidence.value:.4f}"),
        ("msg", finding.evidence),
        ("src", report.metadata.source),
    ]
    attributes = "\t".join(
        f"{key}={leef_escape(value)}" for key, value in pairs if value is not None
    )
    return f"{header}|{attributes}"


# ------------------------------------------------------------------------------ syslog


def _sd_escape(value: str) -> str:
    """RFC 5424 section 6.3.3: escape ``"``, ``\\`` and ``]`` in a param value."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _printable_ascii(value: str, limit: int) -> str:
    """RFC 5424 restricts HOSTNAME and APP-NAME to printable ASCII of a bounded length."""
    cleaned = "".join(character for character in value if 33 <= ord(character) <= 126)
    return cleaned[:limit] or NIL


def to_syslog(
    finding: Finding,
    report: Report,
    *,
    message: str | None = None,
    hostname: str = NIL,
    app_name: str = "ipsec-sentinel",
    procid: str = NIL,
    facility: int = FACILITY_LOCAL0,
    timestamp: datetime | None = None,
    max_octets: int = MAX_SYSLOG_OCTETS,
) -> str:
    """One finding as an RFC 5424 syslog line.

    Truncated to ``max_octets`` if necessary, and truncated **in the message body only**.
    A collector that cannot parse the header discards the event entirely, so a length
    limit that could eat into the header would turn a long finding into no alert at all.
    """
    when = (timestamp or report.metadata.generated_at).astimezone(UTC)
    structured = (
        f"[{SD_ID}"
        f' ruleId="{_sd_escape(finding.rule_id)}"'
        f' severity="{_sd_escape(finding.severity.value)}"'
        f' assurance="{"verified" if finding.is_deterministic else "inferred"}"'
        f' tunnelId="{_sd_escape(finding.tunnel_id or NIL)}"'
        f' source="{_sd_escape(report.metadata.source)}"'
        "]"
    )
    header = " ".join(
        [
            f"<{priority(finding.severity, facility)}>{SYSLOG_VERSION}",
            when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            _printable_ascii(hostname, 255),
            _printable_ascii(app_name, 48),
            _printable_ascii(procid, 128),
            _printable_ascii(finding.rule_id, 32),
            structured,
        ]
    )
    body = message if message is not None else f"{finding.title}: {finding.evidence}"
    return _fit(header, body, max_octets)


def _fit(header: str, body: str, max_octets: int) -> str:
    """Assemble header and message, trimming the message to fit the octet budget."""
    prefix = f"{header} {BOM}"
    available = max_octets - len(prefix.encode("utf-8"))
    encoded = body.encode("utf-8")
    if available <= 0:
        # Nothing left for a message. The header alone is still a valid, useful event.
        return header
    if len(encoded) <= available:
        return prefix + body

    marker = TRUNCATION_MARKER.encode("utf-8")
    keep = max(0, available - len(marker))
    # Decode with errors="ignore" so a cut that lands mid-character drops the partial
    # code point rather than emitting invalid UTF-8 the collector may reject.
    return prefix + encoded[:keep].decode("utf-8", errors="ignore") + TRUNCATION_MARKER


# ------------------------------------------------------------------------- emitting


@dataclass
class EmitResult:
    """What an emit attempt achieved. Never raises for an unreachable collector."""

    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.failed == 0

    def summary(self) -> str:
        if self.complete:
            return f"{self.sent} event(s) sent"
        return f"{self.sent} sent, {self.failed} failed: {'; '.join(self.errors[:3])}"


class SyslogEmitter:
    """Send syslog lines to a collector over UDP or TCP.

    Constructed only when a caller asks for it. Nothing in the analysis path creates
    one, because a passive tool that opens an outbound connection on its own is no
    longer straightforwardly passive, whatever it sends.

    An unreachable collector is recorded and returned, never raised. A SIEM that is down
    is a normal operational condition, and losing a completed assessment because the
    last step could not deliver it would be the wrong trade every time.
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        transport: str = "udp",
        timeout_s: float = 5.0,
    ) -> None:
        if transport not in ("udp", "tcp"):
            raise ValueError(f"transport must be 'udp' or 'tcp', got {transport!r}")
        self.host = host
        self.port = port
        self.transport = transport
        self.timeout_s = timeout_s

    def emit(self, messages: Iterable[str]) -> EmitResult:
        lines = list(messages)
        if not lines:
            return EmitResult()
        if self.transport == "udp":
            return self._emit_udp(lines)
        return self._emit_tcp(lines)

    def _emit_udp(self, lines: list[str]) -> EmitResult:
        result = EmitResult()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            result.failed = len(lines)
            result.errors.append(f"could not open a UDP socket: {exc}")
            return result
        with sock:
            sock.settimeout(self.timeout_s)
            for line in lines:
                try:
                    sock.sendto(line.encode("utf-8"), (self.host, self.port))
                    result.sent += 1
                except OSError as exc:
                    result.failed += 1
                    result.errors.append(f"{self.host}:{self.port}: {exc}")
        return result

    def _emit_tcp(self, lines: list[str]) -> EmitResult:
        result = EmitResult()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
                for line in lines:
                    # RFC 6587 octet counting: a stream needs framing, and the
                    # length prefix is the framing that does not break on a message
                    # containing a newline.
                    payload = line.encode("utf-8")
                    sock.sendall(f"{len(payload)} ".encode() + payload)
                    result.sent += 1
        except OSError as exc:
            result.failed = len(lines) - result.sent
            result.errors.append(f"{self.host}:{self.port}: {exc}")
        return result


def report_to_syslog(report: Report, **kwargs: object) -> list[str]:
    """Every finding in the report as a syslog line, most severe first."""
    findings = sorted(report.all_findings, key=lambda f: f.severity.rank)
    return [to_syslog(finding, report, **kwargs) for finding in findings]  # type: ignore[arg-type]


def report_to_cef(report: Report) -> list[str]:
    return [to_cef(finding, report) for finding in report.all_findings]


def report_to_leef(report: Report) -> list[str]:
    return [to_leef(finding, report) for finding in report.all_findings]

"""Tests for SIEM output (build plan Step 9.7).

Escaping gets the most attention, because it is where these formats fail and the failure
is silent. An unescaped pipe in a CEF header does not corrupt one field — it shifts every
field after it, so the collector reads the severity out of the message body and the alert
arrives with the wrong urgency. A payload containing every delimiter at once is pushed
through all three formats.

The emitter is tested against a real socket on a closed port rather than a mock, because
what is being asserted is that an unreachable collector does not take the run down with
it, and a mock would only prove that the mock behaves as written.
"""

from __future__ import annotations

import re
import socket
import threading
from datetime import UTC, datetime

import pytest

from ipsec_sentinel.assess.inventory import Inventory
from ipsec_sentinel.models import Confidence, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.models import Report
from ipsec_sentinel.report.siem import (
    BOM,
    CEF_SEVERITY,
    FACILITY_LOCAL0,
    MAX_SYSLOG_OCTETS,
    SD_ID,
    SYSLOG_SEVERITY,
    EmitResult,
    SyslogEmitter,
    SyslogSeverity,
    cef_escape_extension,
    cef_escape_header,
    leef_escape,
    priority,
    report_to_cef,
    report_to_leef,
    report_to_syslog,
    to_cef,
    to_leef,
    to_syslog,
)

NOW = datetime(2026, 6, 1, 12, 30, 45, 123000, tzinfo=UTC)

CEF_HEADER_FIELDS = 7


def cef_fields(line: str) -> list[str]:
    """Split a CEF line the way a parser does: seven header fields, then the rest.

    The extension is *not* split further. CEF escapes ``=`` and ``\\`` in extension
    values but deliberately not ``|``, because extension parsing is key/value rather
    than positional — so a pipe there is legal and must not be read as a delimiter.
    """
    return re.split(r"(?<!\\)\|", line, maxsplit=CEF_HEADER_FIELDS)


# Every delimiter these formats use, in one string.
NASTY = 'pipe| equals= back\\slash tab\there\nnewline "quote" bracket]'


def finding(
    rule_id: str = "CRY-05",
    severity: Severity = Severity.CRITICAL,
    *,
    evidence: str = "the responder selected ENCR_3DES",
    title: str = "3DES negotiated",
    technique: str | None = "T1600.001",
    confidence: float | None = None,
    tunnel_id: str | None = "t-001",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        evidence=evidence,
        standard_ref="RFC 8221 section 5",
        attack_technique=technique,
        remediation_hint="Move to AES-GCM.",
        confidence=None if confidence is None else Confidence(value=confidence, method="m"),
        tunnel_id=tunnel_id,
    )


def report(findings: list[Finding] | None = None) -> Report:
    given = findings if findings is not None else [finding()]
    return build_report(
        [
            TunnelAssessment(
                tunnel_id="t-001",
                endpoints=("203.0.113.1", "198.51.100.1"),
                findings=given,
                score=20,
                grade="F",
            )
        ],
        Inventory(),
        "nist_800_77r1",
        source="capture_outer.pcap",
        generated_at=NOW,
    )


class TestCEFFormat:
    def test_the_header_has_seven_fields_before_the_extension(self) -> None:
        line = to_cef(finding(), report())
        assert line.startswith("CEF:0|")
        fields = cef_fields(line)
        assert len(fields) == CEF_HEADER_FIELDS + 1, fields
        assert fields[1] == "IPsecSentinel"
        assert fields[4] == "CRY-05"
        assert fields[6] == str(CEF_SEVERITY[Severity.CRITICAL])

    def test_the_severity_is_within_the_cef_range(self) -> None:
        for severity in Severity:
            assert 0 <= CEF_SEVERITY[severity] <= 10

    def test_severities_are_spread_rather_than_bunched(self) -> None:
        """A collector's own thresholds are useless if everything maps to 10."""
        values = [CEF_SEVERITY[s] for s in Severity]
        assert len(set(values)) == len(values)
        assert CEF_SEVERITY[Severity.CRITICAL] > CEF_SEVERITY[Severity.INFO]

    def test_the_extension_carries_the_evidence_and_the_tunnel(self) -> None:
        line = to_cef(finding(), report())
        assert "cs1Label=tunnelId" in line
        assert "cs1=t-001" in line
        assert "ENCR_3DES" in line

    def test_a_verified_finding_is_labelled_verified(self) -> None:
        assert "cs4=verified" in to_cef(finding(), report())

    def test_an_inferred_finding_is_labelled_and_carries_its_confidence(self) -> None:
        """An analyst triaging the alert must be able to tell a fact from an estimate."""
        line = to_cef(finding(confidence=0.71), report())
        assert "cs4=inferred" in line
        assert "cn1Label=confidence" in line
        assert "cn1=0.7100" in line

    def test_a_verified_finding_carries_no_confidence_field(self) -> None:
        line = to_cef(finding(), report())
        assert "cn1=" not in line
        assert "cn1Label" not in line

    def test_an_absent_technique_is_omitted_not_empty(self) -> None:
        line = to_cef(finding(technique=None), report())
        assert "cs3=" not in line


class TestCEFEscaping:
    def test_a_pipe_in_a_header_field_is_escaped(self) -> None:
        assert cef_escape_header("a|b") == "a\\|b"

    def test_a_backslash_is_escaped_before_the_pipe(self) -> None:
        """Escaping the pipe first would leave a literal backslash before a live delimiter."""
        assert cef_escape_header("a\\|b") == "a\\\\\\|b"

    def test_an_equals_sign_in_an_extension_is_escaped(self) -> None:
        assert cef_escape_extension("k=v") == "k\\=v"

    def test_a_newline_in_an_extension_becomes_a_literal(self) -> None:
        assert cef_escape_extension("a\nb") == "a\\nb"
        assert cef_escape_extension("a\r\nb") == "a\\nb"

    def test_a_hostile_payload_does_not_add_header_fields(self) -> None:
        """The real risk: a shifted field means the wrong severity reaches the analyst."""
        line = to_cef(finding(title=NASTY, evidence=NASTY), report())
        fields = cef_fields(line)
        assert len(fields) == CEF_HEADER_FIELDS + 1, fields
        assert fields[6] == str(CEF_SEVERITY[Severity.CRITICAL])
        assert "\\|" in fields[5], "the pipe in the title should have been escaped"

    def test_a_hostile_payload_leaves_no_raw_newline(self) -> None:
        line = to_cef(finding(title=NASTY, evidence=NASTY), report())
        assert "\n" not in line
        assert "\r" not in line

    def test_a_pipe_in_an_extension_value_is_left_alone(self) -> None:
        """Spec-correct: extension parsing is key/value, so a pipe there is not a delimiter.

        Escaping it anyway would produce a literal backslash in the analyst's message
        field for no benefit.
        """
        assert cef_escape_extension("a|b") == "a|b"


class TestLEEFFormat:
    def test_it_declares_leef_1_0_with_five_header_fields(self) -> None:
        line = to_leef(finding(), report())
        assert line.startswith("LEEF:1.0|")
        header, _, _ = line.partition("|sev=")
        assert len(re.split(r"(?<!\\)\|", header)) == 5

    def test_attributes_are_tab_delimited(self) -> None:
        line = to_leef(finding(), report())
        attributes = line.split("|", 5)[5]
        assert "\t" in attributes
        for pair in attributes.split("\t"):
            assert "=" in pair

    def test_it_carries_the_assurance_label(self) -> None:
        assert "assurance=verified" in to_leef(finding(), report())
        assert "assurance=inferred" in to_leef(finding(confidence=0.5), report())

    def test_a_tab_in_a_value_is_escaped(self) -> None:
        """An unescaped tab ends the field early and misreads every attribute after it."""
        assert leef_escape("a\tb") == "a\\tb"

    def test_a_hostile_payload_does_not_add_attributes(self) -> None:
        line = to_leef(finding(evidence=NASTY), report())
        attributes = line.split("|", 5)[5].split("\t")
        keys = [pair.split("=", 1)[0] for pair in attributes]
        assert keys == [
            "sev",
            "cat",
            "tunnelId",
            "standard",
            "attackTechnique",
            "assurance",
            "msg",
            "src",
        ]

    def test_a_hostile_payload_leaves_no_raw_newline(self) -> None:
        line = to_leef(finding(title=NASTY, evidence=NASTY), report())
        assert "\n" not in line and "\r" not in line


class TestSyslog:
    def test_it_matches_the_rfc_5424_shape(self) -> None:
        line = to_syslog(finding(), report(), hostname="sensor01")
        pattern = (
            r"^<\d{1,3}>1 "
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z "
            r"\S+ \S+ \S+ \S+ \[.+\]"
        )
        assert re.match(pattern, line), line

    def test_the_priority_is_facility_times_eight_plus_severity(self) -> None:
        assert priority(Severity.CRITICAL) == FACILITY_LOCAL0 * 8 + SyslogSeverity.CRITICAL
        assert priority(Severity.INFO) == FACILITY_LOCAL0 * 8 + SyslogSeverity.INFORMATIONAL

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, SyslogSeverity.CRITICAL),
            (Severity.HIGH, SyslogSeverity.ERROR),
            (Severity.MEDIUM, SyslogSeverity.WARNING),
            (Severity.LOW, SyslogSeverity.NOTICE),
            (Severity.INFO, SyslogSeverity.INFORMATIONAL),
        ],
    )
    def test_the_severity_mapping(self, severity: Severity, expected: SyslogSeverity) -> None:
        assert SYSLOG_SEVERITY[severity] is expected

    def test_every_severity_is_mapped(self) -> None:
        assert set(SYSLOG_SEVERITY) == set(Severity)

    def test_the_structured_data_carries_the_finding(self) -> None:
        line = to_syslog(finding(), report())
        assert SD_ID in line
        assert 'ruleId="CRY-05"' in line
        assert 'assurance="verified"' in line
        assert 'tunnelId="t-001"' in line

    def test_an_inferred_finding_says_so_in_structured_data(self) -> None:
        assert 'assurance="inferred"' in to_syslog(finding(confidence=0.6), report())

    def test_the_message_is_preceded_by_a_bom(self) -> None:
        """RFC 5424 section 6.4: a BOM marks the MSG as UTF-8."""
        assert BOM in to_syslog(finding(), report())

    def test_a_message_stays_under_the_octet_limit(self) -> None:
        line = to_syslog(finding(), report())
        assert len(line.encode("utf-8")) <= MAX_SYSLOG_OCTETS

    def test_a_very_long_finding_is_truncated_not_dropped(self) -> None:
        long_finding = finding(evidence="x" * 5000)
        line = to_syslog(long_finding, report())
        assert len(line.encode("utf-8")) <= MAX_SYSLOG_OCTETS
        assert "[truncated]" in line

    def test_truncation_never_eats_the_header(self) -> None:
        """A collector that cannot parse the header discards the event entirely."""
        line = to_syslog(finding(evidence="x" * 5000), report())
        assert line.startswith("<")
        assert SD_ID in line
        assert 'ruleId="CRY-05"' in line

    def test_truncation_leaves_valid_utf8(self) -> None:
        """A cut landing mid-character would emit bytes a collector may reject."""
        line = to_syslog(finding(evidence="é" * 3000), report())
        encoded = line.encode("utf-8")
        assert len(encoded) <= MAX_SYSLOG_OCTETS
        assert encoded.decode("utf-8") == line

    def test_structured_data_delimiters_are_escaped(self) -> None:
        line = to_syslog(finding(rule_id='a"b]c\\d'), report())
        assert '\\"' in line
        assert "\\]" in line

    def test_a_hostname_is_reduced_to_printable_ascii(self) -> None:
        line = to_syslog(finding(), report(), hostname="sen soré01")
        assert " sor" not in line.split("]")[0].split(">1 ")[1]

    def test_an_absent_hostname_is_the_nil_value(self) -> None:
        assert " - " in to_syslog(finding(), report())

    def test_an_absurdly_small_budget_still_yields_a_valid_header(self) -> None:
        line = to_syslog(finding(), report(), max_octets=40)
        assert line.startswith("<")
        assert SD_ID in line


class TestWholeReportHelpers:
    def test_every_finding_becomes_an_event_in_each_format(self) -> None:
        built = report(
            [
                finding("CRY-05"),
                finding("IKE-03", Severity.HIGH),
                finding("ANOM-01", Severity.MEDIUM, confidence=0.6),
            ]
        )
        assert len(report_to_cef(built)) == 3
        assert len(report_to_leef(built)) == 3
        assert len(report_to_syslog(built)) == 3

    def test_syslog_events_are_ordered_most_severe_first(self) -> None:
        built = report([finding("SA-01", Severity.LOW), finding("CRY-05", Severity.CRITICAL)])
        lines = report_to_syslog(built)
        assert 'ruleId="CRY-05"' in lines[0]
        assert 'ruleId="SA-01"' in lines[1]

    def test_an_empty_report_produces_no_events(self) -> None:
        built = build_report([], Inventory(), "b", source="s", generated_at=NOW)
        assert report_to_cef(built) == []
        assert report_to_syslog(built) == []


class TestTheEmitter:
    def test_an_unreachable_collector_does_not_raise(self) -> None:
        """A SIEM that is down is a normal operational condition.

        Losing a completed assessment because the last step could not deliver it would
        be the wrong trade every time.
        """
        emitter = SyslogEmitter("127.0.0.1", _closed_port(), transport="tcp", timeout_s=1.0)
        result = emitter.emit(["<134>1 - - - - - - test"])
        assert result.failed == 1
        assert result.sent == 0
        assert result.errors
        assert not result.complete

    def test_a_bad_hostname_does_not_raise(self) -> None:
        emitter = SyslogEmitter("no-such-host.invalid", 514, transport="tcp", timeout_s=1.0)
        result = emitter.emit(["<134>1 - - - - - - test"])
        assert result.failed == 1
        assert "no-such-host.invalid" in result.errors[0]

    def test_udp_to_nowhere_is_reported_as_sent(self) -> None:
        """UDP is fire-and-forget; claiming delivery would be the lie, not this."""
        emitter = SyslogEmitter("127.0.0.1", _closed_port(), transport="udp")
        result = emitter.emit(["<134>1 - - - - - - test"])
        assert result.sent == 1

    def test_a_real_tcp_collector_receives_the_events(self) -> None:
        received: list[bytes] = []
        with _tcp_collector(received) as port:
            emitter = SyslogEmitter("127.0.0.1", port, transport="tcp", timeout_s=5.0)
            result = emitter.emit(["<134>1 first", "<134>1 second"])
        assert result.sent == 2
        assert result.complete
        payload = b"".join(received)
        assert b"first" in payload
        assert b"second" in payload

    def test_tcp_framing_is_octet_counted(self) -> None:
        """A stream needs framing that does not break on a message containing a newline."""
        received: list[bytes] = []
        with _tcp_collector(received) as port:
            SyslogEmitter("127.0.0.1", port, transport="tcp").emit(["abc"])
        assert b"".join(received) == b"3 abc"

    def test_emitting_nothing_is_a_no_op(self) -> None:
        result = SyslogEmitter("127.0.0.1", 1).emit([])
        assert result == EmitResult()
        assert result.complete

    def test_an_unknown_transport_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError, match="udp"):
            SyslogEmitter("127.0.0.1", 514, transport="carrier-pigeon")

    def test_the_result_summarises_itself(self) -> None:
        assert "2 event(s) sent" in EmitResult(sent=2).summary()
        assert "failed" in EmitResult(sent=1, failed=1, errors=["boom"]).summary()


def _forbid_sockets(monkeypatch: pytest.MonkeyPatch, what: str) -> None:
    """Make any socket construction an immediate, attributable failure."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(f"{what} opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class TestNothingSendsByAccident:
    """The tool observes and does not act; an analysis run must not dial out."""

    def test_formatting_opens_no_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _forbid_sockets(monkeypatch, "formatting")
        built = report()
        report_to_cef(built)
        report_to_leef(built)
        report_to_syslog(built)

    def test_building_a_report_opens_no_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _forbid_sockets(monkeypatch, "building a report")
        report()

    def test_constructing_an_emitter_opens_no_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The connection is made when events are sent, not when the emitter is made."""
        _forbid_sockets(monkeypatch, "constructing an emitter")
        SyslogEmitter("127.0.0.1", 514)


def _closed_port() -> int:
    """A port nothing is listening on: bind, read the number, release it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    return port


class _tcp_collector:  # noqa: N801 — used as a context manager, not a type
    """A single-connection TCP listener that records what it receives."""

    def __init__(self, sink: list[bytes]) -> None:
        self.sink = sink
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = int(self.server.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            connection, _ = self.server.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(5.0)
            while True:
                try:
                    chunk = connection.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                self.sink.append(chunk)

    def __enter__(self) -> int:
        self.thread.start()
        return self.port

    def __exit__(self, *exc: object) -> None:
        self.thread.join(timeout=5.0)
        self.server.close()

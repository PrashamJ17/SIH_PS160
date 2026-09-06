#!/usr/bin/env python3
"""Execute the M9 acceptance checklist and report pass/fail per item.

Every item runs the thing it claims to check, against a **real capture from the sweep
corpus** rather than a constructed report. The offline check disables networking for the
duration of the render rather than inspecting the markup for URLs, because the question
the criterion asks is whether the report works with no network, not whether it looks as
though it would.
"""

from __future__ import annotations

import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from jsonschema import Draft202012Validator  # noqa: E402

from ipsec_sentinel.analyse import analyse_capture, attach_inferences  # noqa: E402
from ipsec_sentinel.assess.inventory import Inventory  # noqa: E402
from ipsec_sentinel.report.build import build_report  # noqa: E402
from ipsec_sentinel.report.export_json import export_json, report_schema  # noqa: E402
from ipsec_sentinel.report.models import Report  # noqa: E402
from ipsec_sentinel.report.render_html import render_html  # noqa: E402
from ipsec_sentinel.report.render_pdf import page_count, pdf_available, render_pdf  # noqa: E402

SWEEP: Final = REPO_ROOT / "data" / "raw" / "sweep"
MAX_REASONABLE_PAGES: Final = 40


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def captures() -> list[Path]:
    return sorted(SWEEP.glob("*/capture_outer.pcap")) if SWEEP.is_dir() else []


def _report() -> tuple[Report, Path]:
    found = captures()
    if not found:
        raise FileNotFoundError("the sweep corpus is not present")
    capture = found[0]
    return analyse_capture(capture), capture


class _NoNetwork:
    """Make every outbound socket attempt fail for the duration of the block.

    Stronger than grepping the HTML for ``http://``: it answers the criterion's actual
    question. A renderer that resolved a font, fetched a schema or phoned home would
    raise here rather than merely look suspicious.
    """

    def __init__(self) -> None:
        self.saved: dict[str, Any] = {}

    def __enter__(self) -> _NoNetwork:
        def refuse(*_args: object, **_kwargs: object) -> None:
            raise OSError("network disabled for this check")

        for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
            self.saved[name] = getattr(socket, name)
            setattr(socket, name, refuse)
        return self

    def __exit__(self, *exc: object) -> None:
        for name, original in self.saved.items():
            setattr(socket, name, original)


# --------------------------------------------------------------------- the checklist


def check_full_report_from_a_real_capture() -> Check:
    name = "Full report generated from a real dataset capture"
    found = captures()
    if not found:
        return Check(name, "FAIL", "the sweep corpus is not present")
    report, capture = _report()
    sections = {
        "inventory": len(report.inventory.entries),
        "section A": len(report.section_a_verified),
        "section B": len(report.section_b_inferred),
        "exposure": len(report.metadata_exposure),
        "threat matrix": len(report.threat_matrix),
        "pqc": len(report.pqc.entries),
    }
    if report.executive.tunnels_assessed < 1:
        return Check(name, "FAIL", f"{capture.parent.name} yielded no tunnels")
    return Check(
        name,
        "PASS",
        f"{capture.parent.name}: {report.executive.tunnels_assessed} tunnel(s), "
        f"grade {report.executive.estate_grade} ({report.executive.estate_score}/100). "
        f"Sections populated: {sections}. "
        f"{len(found)} corpus captures available.",
    )


def check_section_a_is_deterministic_only() -> Check:
    name = "Section A contains only deterministic findings (verified by validator)"
    report, _ = _report()
    offenders = [f.rule_id for f in report.section_a_verified if f.confidence is not None]
    if offenders:
        return Check(name, "FAIL", f"inferred findings in Section A: {offenders}")

    # Prove the validator rejects the violation rather than that the data happens to
    # comply: a check that only ever sees valid input proves nothing about the guard.
    inferred = next((f for f in report.all_findings if f.confidence is not None), None)
    if inferred is None:
        from ipsec_sentinel.models import Confidence, Finding, Severity

        inferred = Finding(
            rule_id="PROBE-01",
            title="probe",
            severity=Severity.LOW,
            evidence="e",
            standard_ref="r",
            remediation_hint="h",
            confidence=Confidence(value=0.5, method="probe"),
        )
    try:
        Report(
            metadata=report.metadata,
            executive=report.executive,
            inventory=Inventory(),
            section_a_verified=[inferred],
        )
    except Exception as exc:  # the validator must refuse this
        return Check(
            name,
            "PASS",
            f"{len(report.section_a_verified)} finding(s), all deterministic; the "
            f"validator refuses an inferred finding in Section A "
            f"({type(exc).__name__})",
        )
    return Check(name, "FAIL", "the validator accepted an inferred finding in Section A")


def check_section_b_is_inferred_only() -> Check:
    name = "Section B contains only inferred findings with confidence"
    report, _ = _report()
    offenders = [f.rule_id for f in report.section_b_inferred if f.confidence is None]
    if offenders:
        return Check(name, "FAIL", f"deterministic findings in Section B: {offenders}")

    deterministic = next((f for f in report.all_findings if f.confidence is None), None)
    if deterministic is None:
        return Check(name, "FAIL", "no deterministic finding available to probe with")
    try:
        Report(
            metadata=report.metadata,
            executive=report.executive,
            inventory=Inventory(),
            section_b_inferred=[deterministic],
        )
    except Exception as exc:
        return Check(
            name,
            "PASS",
            f"{len(report.section_b_inferred)} finding(s), each carrying a confidence; "
            f"the validator refuses a deterministic finding in Section B "
            f"({type(exc).__name__})",
        )
    return Check(name, "FAIL", "the validator accepted a deterministic finding in Section B")


def check_html_opens_with_no_network() -> Check:
    name = "HTML opens with no network access"
    report, _ = _report()
    with _NoNetwork():
        html = render_html(report)
    if "<script" in html.lower() or "<link" in html.lower():
        return Check(name, "FAIL", "the document loads an external resource")
    return Check(
        name,
        "PASS",
        f"{len(html)} characters rendered with every socket call disabled; no script or "
        f"link element, all CSS inline",
    )


def check_pdf_renders() -> Check:
    name = "PDF renders"
    if not pdf_available():
        return Check(
            name,
            "FAIL",
            "WeasyPrint's native dependencies are unavailable on this machine",
        )
    report, _ = _report()
    with _NoNetwork():
        data = render_pdf(report)
        pages = page_count(report)
    if not data.startswith(b"%PDF-"):
        return Check(name, "FAIL", "the output is not a PDF")
    if not 1 <= pages <= MAX_REASONABLE_PAGES:
        return Check(name, "FAIL", f"{pages} pages is not a reasonable length")
    return Check(
        name,
        "PASS",
        f"{len(data)} bytes, {pages} page(s), rendered with networking disabled",
    )


def check_json_validates_against_the_schema() -> Check:
    name = "JSON validates against the published schema"
    report, _ = _report()
    payload = json.loads(export_json(report))
    validator = Draft202012Validator(report_schema())
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        return Check(name, "FAIL", "; ".join(str(e.message) for e in errors[:3]))
    restored = Report.model_validate(payload)
    if restored != report:
        return Check(name, "FAIL", "the report did not survive the round trip")
    return Check(
        name,
        "PASS",
        f"validates against schema {report.metadata.schema_version} and round-trips "
        f"back into the model unchanged",
    )


def check_exposure_for_a_grade_a_tunnel() -> Check:
    """The section's whole point: a soundly configured tunnel still reveals a great deal.

    Searched by the tunnel's *own* grade rather than the estate's. A capture can hold one
    sound tunnel and one bad one, and it is the sound tunnel this criterion is about.
    """
    name = "Metadata exposure present for a grade-A tunnel"
    from ipsec_sentinel.analyse import assess_tunnel, read_tunnels

    for capture in captures():
        tunnels = read_tunnels(capture)
        graded = [(t, assess_tunnel(t)) for t in tunnels]
        best = [(t, a) for t, a in graded if a.grade == "A"]
        if not best:
            continue
        report = analyse_capture(capture)
        tunnel, assessment = best[0]
        entry = next(
            (e for e in report.metadata_exposure.entries if e.tunnel_id == tunnel.tunnel_id),
            None,
        )
        if entry is None:
            return Check(
                name,
                "FAIL",
                f"tunnel {tunnel.tunnel_id} is grade A but has no exposure entry",
            )
        return Check(
            name,
            "PASS",
            f"{capture.parent.name}: tunnel {entry.tunnel_id} scores "
            f"{assessment.score}/100 (grade {assessment.grade}) and still discloses "
            f"{entry.endpoints[0]} to {entry.endpoints[1]}, {entry.total_bytes} bytes in "
            f"{entry.session_count} session(s) across hours {entry.active_hours}"
            + (
                f", inferred as {entry.inferred_traffic}"
                if entry.inferred_traffic
                else ", with no application class stated"
            ),
        )

    return Check(
        name,
        "FAIL",
        f"no grade-A tunnel found in {len(captures())} corpus captures, so the "
        f"criterion could not be demonstrated",
    )


def check_the_executive_summary_reads_plainly() -> Check:
    """Automates what can be automated; the judgement itself is recorded in PROGRESS.md."""
    name = "Executive summary is understandable by a non-technical reader"
    report, _ = _report()
    headline = report.executive.headline
    jargon = [
        term
        for term in ("3DES", "AES", "Diffie", "IKEv", "SHA", "ESP", "SPI", "MODP", "PRF")
        if term in headline
    ]
    problems: list[str] = []
    if jargon:
        problems.append(f"jargon in the headline: {jargon}")
    if not headline[0].isupper() or not headline.rstrip().endswith("."):
        problems.append("the headline is not a complete sentence")
    for broken in ("1 tunnels", "tunnel examined are", "1 tunnel are"):
        if broken in headline:
            problems.append(f"broken agreement: {broken!r}")
    if not report.executive.key_points:
        problems.append("no key points")
    if problems:
        return Check(name, "FAIL", "; ".join(problems))
    return Check(
        name,
        "PASS",
        f"no algorithm names, grammatical, {len(report.executive.key_points)} key "
        f'point(s). Headline: "{headline}"',
    )


def check_an_empty_capture_is_handled() -> Check:
    """Not on the plan's list. A demo that crashes on an empty capture is a lost demo."""
    name = "A capture with no tunnels produces a valid report rather than an error"
    report = build_report([], Inventory(), "nist_800_77r1", source="empty.pcap")
    problems = []
    if report.executive.estate_grade != "A":
        problems.append(f"graded {report.executive.estate_grade}; nothing observed is not failure")
    if "No IPsec tunnels were found" not in report.executive.headline:
        problems.append("the headline does not say the capture was empty")
    try:
        render_html(report)
        json.loads(export_json(report))
    except Exception as exc:  # reported as a failed check, not raised
        problems.append(f"rendering failed: {type(exc).__name__}: {exc}")
    if problems:
        return Check(name, "FAIL", "; ".join(problems))
    return Check(name, "PASS", "renders to HTML and JSON, and says plainly that it found nothing")


def check_inferences_are_carried_when_supplied() -> Check:
    """Section B is empty on this corpus, so the path must be exercised deliberately."""
    name = "A supplied inference reaches Section B with its confidence"
    found = captures()
    if not found:
        return Check(name, "FAIL", "the sweep corpus is not present")
    from ipsec_sentinel.analyse import assess_tunnel, read_tunnels
    from ipsec_sentinel.assess.inventory import build_inventory

    tunnels = read_tunnels(found[0])
    assessments = [
        attach_inferences(assess_tunnel(t), traffic="voip", traffic_confidence=0.81)
        for t in tunnels
    ]
    report = build_report(
        assessments, build_inventory(tunnels), "nist_800_77r1", source=found[0].name
    )
    stated = [e for e in report.metadata_exposure.entries if e.inferred_traffic]
    if not stated:
        return Check(name, "FAIL", "the inference did not reach the exposure section")
    confidence = stated[0].inferred_traffic_confidence
    if confidence is None:
        return Check(name, "FAIL", "the class arrived without its confidence")
    html = render_html(report)
    if f"{confidence.value:.2f}" not in html:
        return Check(name, "FAIL", "the rendered report omits the confidence value")
    return Check(
        name,
        "PASS",
        f"{len(stated)} entry(ies) carry an inferred class with confidence "
        f"{confidence.value:.2f}, and the value is printed in the HTML",
    )


CHECKS = [
    check_full_report_from_a_real_capture,
    check_section_a_is_deterministic_only,
    check_section_b_is_inferred_only,
    check_html_opens_with_no_network,
    check_pdf_renders,
    check_json_validates_against_the_schema,
    check_exposure_for_a_grade_a_tunnel,
    check_the_executive_summary_reads_plainly,
    check_an_empty_capture_is_handled,
    check_inferences_are_carried_when_supplied,
]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M9 acceptance checklist.")
    parser.add_argument("--only", help="run only checks whose name contains this substring")
    args = parser.parse_args(argv)

    selected = [c for c in CHECKS if not args.only or args.only in c.__name__]
    print("M9 — Reporting complete\n")
    results = [check() for check in selected]
    for result in results:
        print(result)
        print()

    failed = [r for r in results if r.status == "FAIL"]
    blocked = [r for r in results if r.status == "BLOCKED"]
    passed = len(results) - len(failed) - len(blocked)
    print(f"{passed}/{len(results)} passed, {len(failed)} failed, {len(blocked)} blocked")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

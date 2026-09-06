"""Assemble a report from assessed tunnels.

The routing rule is one line — ``confidence is None`` means Section A, otherwise
Section B — and everything else here exists to make that routing survive contact with a
reader. Findings arrive per tunnel and leave as two flat lists, so each one is stamped
with the tunnel it came from on the way: "3DES is in use" without saying where is a fact
nobody can act on.

The executive summary is generated from the same findings it summarises rather than
passed in, because a summary assembled separately drifts from the body, and the summary
is the part that gets read. The model validates the two against each other as well; this
builder simply cannot produce a mismatch in the first place.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from ipsec_sentinel.assess.enrich import corpus_status
from ipsec_sentinel.assess.inventory import Inventory
from ipsec_sentinel.assess.scoring import score_estate
from ipsec_sentinel.models import Finding, Severity, TunnelAssessment
from ipsec_sentinel.remediate.models import ChangePackage
from ipsec_sentinel.report.exposure import build_exposure
from ipsec_sentinel.report.models import (
    EnrichmentStatus,
    ExecutiveSummary,
    MetadataExposure,
    PQCSummary,
    Report,
    ReportMetadata,
    ThreatMatrix,
)
from ipsec_sentinel.report.threat_matrix import build_threat_matrix
from ipsec_sentinel.version import git_dirty, git_sha, tool_version

PERFECT_SCORE: Final = 100


def route(findings: Sequence[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (parsed, inferred).

    The whole Section A / Section B distinction, in one function, so there is exactly
    one place in the codebase that decides it.
    """
    verified = [finding for finding in findings if finding.confidence is None]
    inferred = [finding for finding in findings if finding.confidence is not None]
    return verified, inferred


def _attributed(assessments: Sequence[TunnelAssessment]) -> list[Finding]:
    """Every finding, stamped with the tunnel it belongs to.

    An existing ``tunnel_id`` is left alone: a caller who has already attributed a
    finding knows something this function does not.
    """
    stamped: list[Finding] = []
    for assessment in assessments:
        for finding in assessment.findings:
            if finding.tunnel_id is None:
                finding = finding.model_copy(update={"tunnel_id": assessment.tunnel_id})
            stamped.append(finding)
    return stamped


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular}" if count == 1 else f"{count} {plural or singular + 's'}"


def _subject(count: int) -> tuple[str, str]:
    """The sentence subject for a set of tunnels, and the verb that agrees with it.

    Returned together because getting them from separate places is how a report ends up
    saying "The 1 tunnel examined are soundly configured". The M9 criterion is that a
    non-technical reader understands the summary, and broken agreement in the opening
    sentence costs more credibility than the finding beneath it earns.
    """
    if count == 1:
        return "The tunnel examined", "is"
    return f"The {count} tunnels examined", "are"


def headline(
    assessments: Sequence[TunnelAssessment],
    severities: Counter[Severity],
    score: int,
    grade: str,
) -> str:
    """One sentence for a reader who will read one sentence.

    Written without jargon on purpose: it says "no longer considered safe" rather than
    naming an algorithm, and gives the grade in words a reader already has.
    """
    if not assessments:
        return (
            "No IPsec tunnels were found in this capture, so there is nothing to report "
            "on yet. Check that the capture was taken where the tunnels actually run."
        )

    total = len(assessments)
    subject, verb = _subject(total)
    scored = f"The estate scores {score} out of 100 (grade {grade})."
    critical = severities.get(Severity.CRITICAL, 0)
    high = severities.get(Severity.HIGH, 0)
    minor = sum(severities.values())

    if critical:
        affected = len({f.tunnel_id for f in _critical_findings(assessments)})
        if total == 1:
            opening = "The tunnel examined is"
        else:
            # Phrased to lead with a word rather than a digit. "1 of the 4 tunnels..."
            # is grammatical but opens the document on a numeral, which reads as a
            # statistic rather than a sentence.
            agreement = "is" if affected == 1 else "are"
            opening = f"Of the {total} tunnels examined, {affected} {agreement}"
        return (
            f"{opening} protected by cryptography that is no longer considered safe, "
            f"and should be changed. {scored}"
        )
    if high:
        return (
            f"No immediate crises were found, but "
            f"{_plural(high, 'serious weakness', 'serious weaknesses')} "
            f"{'needs' if high == 1 else 'need'} attention across "
            f"{_plural(total, 'tunnel')}. {scored}"
        )
    if minor:
        return (
            f"{subject} {verb} soundly configured. "
            f"{_plural(minor, 'minor improvement')} "
            f"{'is' if minor == 1 else 'are'} suggested. {scored}"
        )
    return (
        f"{subject} {verb} fully compliant with the selected baseline, scoring "
        f"{score} out of 100 (grade {grade}). Note the exposure section: even a "
        f"correctly configured tunnel reveals who is talking to whom, and when."
    )


def _critical_findings(assessments: Sequence[TunnelAssessment]) -> list[Finding]:
    return [f for f in _attributed(assessments) if f.severity is Severity.CRITICAL]


def key_points(
    inventory: Inventory,
    verified: Sequence[Finding],
    inferred: Sequence[Finding],
) -> list[str]:
    """The three or four things worth saying after the headline."""
    points: list[str] = []
    undocumented = len(inventory.undocumented)
    if undocumented:
        points.append(
            f"{_plural(undocumented, 'tunnel')} carrying traffic "
            f"{'is' if undocumented == 1 else 'are'} not on the documented list. An "
            f"undocumented tunnel is one nobody is maintaining."
        )
    elif inventory.documented_list_supplied:
        points.append("Every observed tunnel appears on the documented list.")
    else:
        points.append(
            "No documented tunnel list was supplied, so this report cannot say whether "
            "any of these tunnels are expected to exist."
        )

    points.append(
        f"{_plural(len(verified), 'finding')} in Section A "
        f"{'is' if len(verified) == 1 else 'are'} read directly from the negotiation "
        f"and can be relied on as evidence. "
        f"{_plural(len(inferred), 'finding')} in Section B "
        f"{'is' if len(inferred) == 1 else 'are'} estimated from traffic patterns and "
        f"{'carries' if len(inferred) == 1 else 'carry'} a stated confidence."
    )

    orphans = len(inventory.orphans)
    if orphans:
        points.append(
            f"{_plural(orphans, 'tunnel')} was carrying protected traffic without a "
            f"negotiation in the capture, so its cryptography could not be assessed. "
            f"Capture across a rekey to see it."
        )
    return points


def _observed_enrichment() -> EnrichmentStatus:
    """What enrichment actually had available on this host, counted from disk."""
    status = corpus_status()
    return EnrichmentStatus(
        attack_techniques=status.attack_techniques,
        cve_cache_entries=status.cve_cache_entries,
    )


def build_report(
    assessments: Sequence[TunnelAssessment],
    inventory: Inventory,
    baseline: str,
    *,
    source: str,
    generated_at: datetime | None = None,
    remediation: Sequence[ChangePackage] = (),
    metadata_exposure: MetadataExposure | None = None,
    threat_matrix: ThreatMatrix | None = None,
    pqc: PQCSummary | None = None,
    criticality: dict[str, float] | None = None,
    enrichment: EnrichmentStatus | None = None,
) -> Report:
    """Route each finding to Section A or B and assemble the report around them.

    The exposure section and the threat matrix are computed here from the same
    assessments, so a caller cannot produce a report that quietly omits them. Passing
    one explicitly overrides it, which is what a caller with a richer source — per-packet
    timestamps rather than flow summaries — needs.

    ``pqc`` is still supplied by the caller: post-quantum grading reads the key exchange
    transforms off the negotiation, which a :class:`TunnelAssessment` does not carry.
    Omitting it yields the empty summary — a report missing a section rather than one
    making something up.
    """
    findings = _attributed(assessments)
    verified, inferred = route(findings)
    severities: Counter[Severity] = Counter(finding.severity for finding in findings)

    estate = score_estate(list(assessments), criticality)
    score = estate.score if assessments else PERFECT_SCORE
    grade = estate.grade if assessments else "A"

    return Report(
        metadata=ReportMetadata(
            source=source,
            generated_at=generated_at or datetime.now(UTC),
            baseline=baseline,
            tool_version=tool_version(),
            git_sha=git_sha(),
            working_tree_dirty=git_dirty(),
            enrichment=enrichment if enrichment is not None else _observed_enrichment(),
        ),
        executive=ExecutiveSummary(
            estate_score=score,
            estate_grade=grade,
            tunnels_assessed=len(assessments),
            tunnels_undocumented=len(inventory.undocumented),
            verified_findings=len(verified),
            inferred_findings=len(inferred),
            findings_by_severity=dict(severities),
            headline=headline(assessments, severities, score, grade),
            key_points=key_points(inventory, verified, inferred),
        ),
        inventory=inventory,
        section_a_verified=verified,
        section_b_inferred=inferred,
        metadata_exposure=(
            metadata_exposure if metadata_exposure is not None else build_exposure(assessments)
        ),
        threat_matrix=(
            threat_matrix if threat_matrix is not None else build_threat_matrix(assessments)
        ),
        remediation=list(remediation),
        # ``is not None`` rather than ``or``: several of these models define
        # __len__, which makes an empty one falsy. An Inventory carrying only
        # documented-but-unobserved tunnels has no entries and is therefore
        # falsy — and ``or`` would silently replace it with a blank one, dropping
        # the very tunnels the operator most wants to hear about.
        pqc=pqc if pqc is not None else PQCSummary(),
    )

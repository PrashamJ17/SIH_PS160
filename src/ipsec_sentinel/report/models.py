"""The report model, and the separation it exists to enforce.

Section A holds findings that were **parsed**. Section B holds findings that were
**inferred**. The distinction is the product: a parsed finding is a fact read off the
wire and can be put in front of an auditor; an inferred one is an estimate from a model
and cannot, however good the model is. Mixing them produces a document that is neither
compliance evidence nor intelligence, because a reader cannot tell which parts are
which.

``Finding.confidence`` is what separates them — ``None`` for parsed, a
:class:`~ipsec_sentinel.models.Confidence` for inferred — and
:meth:`Report.enforce_separation` refuses to build a report that puts one in the other's
section.

That validator raises rather than asserting. The build plan sketches it with ``assert``,
which would be removed by ``python -O``: the guarantee at the centre of the product
would then silently disappear in exactly the deployment most likely to run optimised.
A test pins the behaviour under ``-O``.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ipsec_sentinel.assess.inventory import Inventory
from ipsec_sentinel.assess.rules.pqc import PQCGrade
from ipsec_sentinel.models import Confidence, Finding, Grade, Severity
from ipsec_sentinel.remediate.models import ChangePackage

# 1.1 adds InferenceExplanation and ExposureEntry.explanation. Bumped rather than
# regenerated in place because these models forbid unknown fields, so the published
# schema carries `additionalProperties: false` — a consumer validating new output
# against 1.0 would reject it. The version travels in every report, so a consumer
# validates against the one the payload declares.
SCHEMA_VERSION: Final = "1.1"


class ReportModel(BaseModel):
    """Base for every model in this file, with unknown fields refused.

    Pydantic ignores unknown fields by default, which has two consequences here. A
    report loaded from a future schema would silently lose whatever it did not
    recognise while still validating — data loss that looks like success. And a test
    that sets a field which has since been renamed keeps passing while testing nothing,
    which is exactly how the CVE fields on :class:`ThreatMatrixRow` went unnoticed after
    they moved onto :class:`CVEReference`.

    ``schema_version`` travels with the report so a reader can tell which case it is in.
    """

    model_config = ConfigDict(extra="forbid")


class ReportMetadata(ReportModel):
    """Where this report came from, so a later reader can reproduce it."""

    source: str = Field(min_length=1)
    """The capture or dataset the report describes."""

    generated_at: datetime
    baseline: str = Field(min_length=1)
    tool_version: str = Field(min_length=1)
    git_sha: str | None = None
    working_tree_dirty: bool | None = None
    """``True`` when the build had uncommitted changes, so the SHA is not the whole story.

    ``None`` means the question could not be answered — an installed copy with no
    repository — which is different from "clean" and is recorded as such.
    """

    schema_version: str = SCHEMA_VERSION

    @property
    def provenance(self) -> str:
        if self.git_sha is None:
            return f"{self.tool_version} (revision unknown)"
        suffix = "-dirty" if self.working_tree_dirty else ""
        return f"{self.tool_version} ({self.git_sha}{suffix})"


class ExecutiveSummary(ReportModel):
    """The first page, written for someone who will read only the first page."""

    estate_score: int = Field(ge=0, le=100)
    estate_grade: Grade
    tunnels_assessed: int = Field(ge=0)
    tunnels_undocumented: int = Field(ge=0)
    verified_findings: int = Field(ge=0)
    inferred_findings: int = Field(ge=0)
    findings_by_severity: dict[Severity, int] = Field(default_factory=dict)
    headline: str = Field(min_length=1)
    """One sentence a non-technical reader can act on."""

    key_points: list[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return self.findings_by_severity.get(Severity.CRITICAL, 0)


class InferenceExplanation(ReportModel):
    """Why the model said what it said, in a sentence and in numbers.

    Carried beside the inference rather than in a separate section, because an estimate
    a reader cannot interrogate is one they must either take on trust or ignore, and
    both are worse than a short explanation.
    """

    sentence: str = Field(min_length=1)
    contributions: list[tuple[str, float]] = Field(default_factory=list)
    """Signed SHAP contributions, most influential first."""

    windows: int = Field(default=0, ge=0)
    """How many traffic windows the classification rests on.

    A judgement from one window and one from thirty are different things, and the
    confidence alone does not say which this is.
    """


class ExposureEntry(ReportModel):
    """What an observer learns about one tunnel without breaking any encryption.

    Produced for **every** tunnel, including perfectly configured ones. That is the
    point: strong cryptography protects the contents and not the fact of the
    conversation, and a report that only lists problems never says so.
    """

    tunnel_id: str = Field(min_length=1)
    endpoints: tuple[str, str]
    total_bytes: int = Field(ge=0)
    total_packets: int = Field(ge=0)
    session_count: int = Field(ge=0)
    active_hours: list[int] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    inferred_traffic: str | None = None
    inferred_traffic_confidence: Confidence | None = None
    explanation: InferenceExplanation | None = None

    @model_validator(mode="after")
    def _inference_carries_its_confidence(self) -> ExposureEntry:
        """The same rule as :class:`~ipsec_sentinel.models.TunnelAssessment`.

        An application class stated without a confidence is indistinguishable from a
        parsed fact by the time it reaches a reader, which is the confusion the whole
        architecture exists to prevent.
        """
        if (self.inferred_traffic is None) != (self.inferred_traffic_confidence is None):
            raise ValueError(
                "inferred_traffic and inferred_traffic_confidence must both be present "
                "or both absent; an inference without a confidence reads as a fact"
            )
        if self.explanation is not None and self.inferred_traffic is None:
            raise ValueError(
                "an explanation without an inference explains nothing; it would read as "
                "reasoning for a conclusion the report does not draw"
            )
        for hour in self.active_hours:
            if not 0 <= hour <= 23:
                raise ValueError(f"active_hours must be hours of the day, got {hour}")
        return self


class MetadataExposure(ReportModel):
    """The exposure section: what encryption does not hide."""

    entries: list[ExposureEntry] = Field(default_factory=list)
    note: str = Field(
        default=(
            "Every tunnel below is listed regardless of how well it is configured. "
            "Encryption protects the contents of a conversation, not the fact that it "
            "happened, who took part, when, or how much was said."
        ),
        min_length=1,
    )

    def __len__(self) -> int:
        return len(self.entries)


class CVEReference(ReportModel):
    """A published vulnerability, with the score and the place it came from.

    The identifier, the score and the source are one object rather than three optional
    fields on a row, so a score can never appear without the CVE it belongs to or the
    reference a reader can check it against. The invariant is unrepresentable rather
    than validated.
    """

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    scope_note: str = Field(min_length=1)
    """What the published record actually covers.

    Recorded because relevance is the part that goes wrong. A CVE about one protocol
    attached to a finding about another looks authoritative and is misinformation.
    """

    source: str = Field(min_length=1)


class ThreatMatrixRow(ReportModel):
    """One adversary technique and the tunnels it applies to."""

    technique: str = Field(min_length=1)
    """MITRE ATT&CK technique ID, e.g. ``T1040``."""

    technique_name: str = Field(min_length=1)
    severity: Severity
    """The worst severity among the findings that put this technique in reach."""

    tunnel_ids: list[str] = Field(min_length=1)
    rule_ids: list[str] = Field(min_length=1)
    cves: list[CVEReference] = Field(default_factory=list)
    includes_inferred: bool = False
    """Whether any contributing finding was inferred rather than parsed.

    Carries the Section A / Section B distinction into the matrix. A row that rests
    partly on an estimate must not read as though it rests entirely on the wire.
    """

    @property
    def worst_cvss(self) -> float | None:
        return max((cve.cvss_score for cve in self.cves), default=None)


class ThreatMatrix(ReportModel):
    """Findings crossed with the techniques they enable."""

    rows: list[ThreatMatrixRow] = Field(default_factory=list)
    uncategorised_rules: list[str] = Field(default_factory=list)
    """Findings with no ATT&CK technique mapped, named rather than dropped.

    A matrix that silently omits them under-represents the estate while looking
    complete, and the reader has no way to tell.
    """

    @property
    def techniques(self) -> list[str]:
        return sorted({row.technique for row in self.rows})

    def __len__(self) -> int:
        return len(self.rows)


class PQCEntry(ReportModel):
    tunnel_id: str = Field(min_length=1)
    grade: PQCGrade
    rationale: str = Field(min_length=1)
    post_quantum_groups: list[str] = Field(default_factory=list)
    classical_groups: list[str] = Field(default_factory=list)


class PQCSummary(ReportModel):
    """Post-quantum readiness across the estate."""

    entries: list[PQCEntry] = Field(default_factory=list)
    note: str = Field(
        default=(
            "Traffic captured today can be stored and decrypted later by an adversary "
            "with a cryptographically relevant quantum computer. Readiness is about "
            "traffic already on the wire, not only about future sessions."
        ),
        min_length=1,
    )

    @property
    def worst_grade(self) -> PQCGrade | None:
        return min((entry.grade for entry in self.entries), default=None)

    def count(self, grade: PQCGrade) -> int:
        return sum(1 for entry in self.entries if entry.grade is grade)


class Report(ReportModel):
    """A complete assessment, in the shape a reader consumes it."""

    metadata: ReportMetadata
    executive: ExecutiveSummary
    inventory: Inventory
    section_a_verified: list[Finding] = Field(default_factory=list)
    section_b_inferred: list[Finding] = Field(default_factory=list)
    metadata_exposure: MetadataExposure = Field(default_factory=MetadataExposure)
    threat_matrix: ThreatMatrix = Field(default_factory=ThreatMatrix)
    remediation: list[ChangePackage] = Field(default_factory=list)
    pqc: PQCSummary = Field(default_factory=PQCSummary)

    @model_validator(mode="after")
    def enforce_separation(self) -> Report:
        """Section A is parsed facts only; Section B is inferences only.

        Deliberately a raised exception and not an ``assert``. Assertions are removed
        by ``python -O``, which would delete the product's central guarantee in
        precisely the deployments most likely to enable it — and delete it silently,
        leaving a report that still looks correct.
        """
        misplaced_in_a = [f.rule_id for f in self.section_a_verified if f.confidence is not None]
        if misplaced_in_a:
            raise ValueError(
                f"Section A is for parsed facts, but {misplaced_in_a} carry a "
                f"confidence and are therefore inferences. An estimate presented as "
                f"compliance evidence is the one error this report must not make."
            )
        misplaced_in_b = [f.rule_id for f in self.section_b_inferred if f.confidence is None]
        if misplaced_in_b:
            raise ValueError(
                f"Section B is for inferences, but {misplaced_in_b} carry no confidence "
                f"and are therefore parsed facts. Presenting a fact as an estimate "
                f"understates evidence an auditor is entitled to rely on."
            )
        return self

    @model_validator(mode="after")
    def _the_summary_counts_match_the_sections(self) -> Report:
        """A summary that disagrees with the body is worse than no summary."""
        if self.executive.verified_findings != len(self.section_a_verified):
            raise ValueError(
                f"the executive summary reports {self.executive.verified_findings} "
                f"verified findings, but Section A holds {len(self.section_a_verified)}"
            )
        if self.executive.inferred_findings != len(self.section_b_inferred):
            raise ValueError(
                f"the executive summary reports {self.executive.inferred_findings} "
                f"inferred findings, but Section B holds {len(self.section_b_inferred)}"
            )
        counted = Counter(f.severity for f in self.all_findings)
        declared = {s: n for s, n in self.executive.findings_by_severity.items() if n}
        if declared != {s: n for s, n in counted.items() if n}:
            raise ValueError(
                f"the executive severity counts {declared} do not match the findings "
                f"in the report {dict(counted)}"
            )
        return self

    @property
    def all_findings(self) -> list[Finding]:
        return [*self.section_a_verified, *self.section_b_inferred]

    @property
    def is_empty(self) -> bool:
        return not self.all_findings and len(self.inventory) == 0

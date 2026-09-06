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

from pydantic import BaseModel, Field, model_validator

from ipsec_sentinel.assess.inventory import Inventory
from ipsec_sentinel.assess.rules.pqc import PQCGrade
from ipsec_sentinel.models import Confidence, Finding, Grade, Severity
from ipsec_sentinel.remediate.models import ChangePackage

SCHEMA_VERSION: Final = "1.0"


class ReportMetadata(BaseModel):
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


class ExecutiveSummary(BaseModel):
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


class ExposureEntry(BaseModel):
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
        for hour in self.active_hours:
            if not 0 <= hour <= 23:
                raise ValueError(f"active_hours must be hours of the day, got {hour}")
        return self


class MetadataExposure(BaseModel):
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


class ThreatMatrixRow(BaseModel):
    """One adversary technique and the tunnels it applies to."""

    technique: str = Field(min_length=1)
    """MITRE ATT&CK technique ID, e.g. ``T1040``."""

    technique_name: str = Field(min_length=1)
    severity: Severity
    tunnel_ids: list[str] = Field(min_length=1)
    rule_ids: list[str] = Field(min_length=1)
    cve_id: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)

    @model_validator(mode="after")
    def _a_cvss_score_needs_a_cve(self) -> ThreatMatrixRow:
        if self.cvss_score is not None and self.cve_id is None:
            raise ValueError("a CVSS score without a CVE identifier cannot be checked")
        return self


class ThreatMatrix(BaseModel):
    """Findings crossed with the techniques they enable."""

    rows: list[ThreatMatrixRow] = Field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return sorted({row.technique for row in self.rows})

    def __len__(self) -> int:
        return len(self.rows)


class PQCEntry(BaseModel):
    tunnel_id: str = Field(min_length=1)
    grade: PQCGrade
    rationale: str = Field(min_length=1)
    post_quantum_groups: list[str] = Field(default_factory=list)
    classical_groups: list[str] = Field(default_factory=list)


class PQCSummary(BaseModel):
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


class Report(BaseModel):
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

"""Cross findings with the adversary techniques they put in reach.

A findings list answers "what is wrong". A threat matrix answers "what can somebody do
about it", which is the question that gets a change approved. The mapping is not
invented here: every rule already declares the ATT&CK technique it corresponds to, and
this module groups by that declaration rather than adding a second opinion.

Two things are recorded that a matrix usually leaves out, both for the same reason —
a matrix that looks complete while quietly omitting things is worse than one that admits
its edges.

**Findings with no technique are named, not dropped.** Several rules — anti-replay
window size, SA lifetimes, an unassessable tunnel — have no ATT&CK equivalent. They are
real findings and they are listed in ``uncategorised_rules`` rather than vanishing.

**A row says whether any part of it was inferred.** The Section A / Section B split does
not stop at the findings list. A row built partly from an estimate must not read as
though it rests entirely on the wire.

The CVE catalogue is deliberately small and every entry is checked against its published
record. Relevance is the part that goes wrong: a CVE about one protocol attached to a
finding about another looks authoritative and is misinformation. See
:data:`CVE_CATALOGUE` for the entries and :data:`EXCLUDED_CVES` for one that was
considered and rejected.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from ipsec_sentinel.models import Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.models import CVEReference, ThreatMatrix, ThreatMatrixRow

# MITRE ATT&CK Enterprise. Only the techniques the rule set actually cites: a table of
# every technique in the framework would be a copy of somebody else's data with nothing
# in this project checking that it stayed correct.
ATTACK_TECHNIQUES: Final[dict[str, str]] = {
    "T1040": "Network Sniffing",
    "T1110.002": "Brute Force: Password Cracking",
    "T1550": "Use Alternate Authentication Material",
    "T1592.002": "Gather Victim Host Information: Software",
    "T1600": "Weaken Encryption",
    "T1600.001": "Weaken Encryption: Reduce Key Space",
    "T1600.002": "Weaken Encryption: Disable Crypto Hardware",
    "T1689": "Downgrade Attack",
}

NVD: Final = "https://nvd.nist.gov/vuln/detail/"

SWEET32 = CVEReference(
    cve_id="CVE-2016-2183",
    cvss_score=7.5,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    summary=(
        "Birthday attacks against 64-bit block ciphers recover plaintext from "
        "long-lived encrypted sessions."
    ),
    scope_note=(
        "The published record names IPsec explicitly alongside TLS and SSH, so it "
        "applies directly to a 3DES ESP or IKE proposal."
    ),
    source=f"{NVD}CVE-2016-2183",
)

IKEV1_PSK_DICTIONARY = CVEReference(
    cve_id="CVE-2018-5389",
    cvss_score=5.9,
    cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    summary=(
        "IKEv1 pre-shared key authentication is open to an offline dictionary attack, "
        "recovering a weak key or allowing host impersonation."
    ),
    scope_note=(
        "The published record describes IKEv1 main mode. Aggressive mode is the same "
        "attack under worse conditions — the authentication hash is sent before "
        "encryption begins, so an observer needs only one captured handshake rather "
        "than an active position."
    ),
    source=f"{NVD}CVE-2018-5389",
)

# Rule ID -> the published vulnerabilities that apply to it.
CVE_CATALOGUE: Final[dict[str, tuple[CVEReference, ...]]] = {
    "CRY-05": (SWEET32,),  # 3DES negotiated
    "CRY-08": (SWEET32,),  # CBC with no integrity, on a 64-bit block cipher
    "IKE-02": (IKEV1_PSK_DICTIONARY,),  # IKEv1 in use
    "IKE-03": (IKEV1_PSK_DICTIONARY,),  # aggressive mode with a pre-shared key
}

# Considered and deliberately not mapped. Kept in the source because "why is Logjam not
# here?" is a reasonable question, and the answer is evidence of the standard applied.
EXCLUDED_CVES: Final[dict[str, str]] = {
    "CVE-2015-4000": (
        "Logjam. The published record scopes it to TLS 1.2 and earlier with DHE_EXPORT "
        "ciphersuites. The underlying research on precomputation against 1024-bit MODP "
        "does bear on IKE, but the CVE as registered is a TLS vulnerability, and "
        "attaching it to a weak Diffie-Hellman finding in IPsec would give a "
        "misattribution the authority of a citation. CRY-02 stands on RFC 8247 instead."
    ),
}


def technique_name(technique: str) -> str:
    """The published name, or the identifier itself if it is not in the table.

    An unknown technique is passed through rather than dropped or renamed: the rule
    that cited it knows something this table does not, and inventing a name would be
    worse than showing the bare identifier.
    """
    return ATTACK_TECHNIQUES.get(technique, technique)


def cves_for(rule_id: str) -> tuple[CVEReference, ...]:
    return CVE_CATALOGUE.get(rule_id, ())


def build_threat_matrix(assessments: Sequence[TunnelAssessment]) -> ThreatMatrix:
    """One row per distinct technique, ordered worst severity first.

    A tunnel with no findings contributes to no row, which is the correct behaviour and
    not an omission: the matrix describes what an adversary could do, and a sound tunnel
    offers nothing to describe.
    """
    by_technique: dict[str, list[tuple[str, Finding]]] = {}
    uncategorised: set[str] = set()

    for assessment in assessments:
        for finding in assessment.findings:
            technique = finding.attack_technique
            if technique is None:
                uncategorised.add(finding.rule_id)
                continue
            by_technique.setdefault(technique, []).append((assessment.tunnel_id, finding))

    rows = [_row(technique, contributions) for technique, contributions in by_technique.items()]
    rows.sort(key=lambda row: (row.severity.rank, row.technique))
    return ThreatMatrix(rows=rows, uncategorised_rules=sorted(uncategorised))


def _row(technique: str, contributions: list[tuple[str, Finding]]) -> ThreatMatrixRow:
    findings = [finding for _, finding in contributions]
    cves: dict[str, CVEReference] = {}
    for finding in findings:
        for cve in cves_for(finding.rule_id):
            cves[cve.cve_id] = cve

    return ThreatMatrixRow(
        technique=technique,
        technique_name=technique_name(technique),
        # The worst contributing finding sets the row's severity. Averaging would let a
        # pile of low findings dilute a critical one into something ignorable.
        severity=min((f.severity for f in findings), key=lambda s: s.rank),
        tunnel_ids=sorted({tunnel_id for tunnel_id, _ in contributions}),
        rule_ids=sorted({finding.rule_id for finding in findings}),
        cves=sorted(cves.values(), key=lambda cve: (-cve.cvss_score, cve.cve_id)),
        includes_inferred=any(finding.confidence is not None for finding in findings),
    )


def worst_severity(matrix: ThreatMatrix) -> Severity | None:
    return min((row.severity for row in matrix.rows), key=lambda s: s.rank, default=None)

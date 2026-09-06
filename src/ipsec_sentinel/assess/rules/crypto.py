"""Cryptographic strength rules, CRY-01 to CRY-10.

**Every rule checks every offered proposal, not only the one that was accepted.** That
is the single most important behaviour in this file, and it is what separates a useful
assessment from a reassuring one.

A gateway that negotiated AES-256 today, while also advertising 3DES, will accept 3DES
tomorrow from a peer that offers nothing else. The offer list is the policy; the
accepted proposal is one session's outcome. An assessment that read only the accepted
proposal would give that gateway a clean report and miss the actual exposure entirely —
and it is exactly the mistake a tool makes when it is written to demo well.

So the evidence says which proposal an algorithm appeared in, out of how many, and
whether it was the one selected. "Offered in proposal 2 of 2, not selected in this
session" is a different finding from "selected in this session", and an operator
triaging forty tunnels needs to tell them apart.

Where the responder's reply was not captured, the evidence says the selection is
unknown rather than assuming it was not selected. A capture that started late must not
produce a confident claim about something it never saw.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from ipsec_sentinel.assess.baselines.schema import Baseline
from ipsec_sentinel.assess.framework import DEFAULT_BASELINE
from ipsec_sentinel.models import Finding, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.parser.constants import dh_security_bits
from ipsec_sentinel.parser.correlate import Tunnel

# Baselines. "default" is the general-purpose rule set; "strict" adds rules that are
# only defensible where a policy demands them, such as requiring AES-256.
BASELINE_STRICT = "strict"
ALL_BASELINES = [DEFAULT_BASELINE, BASELINE_STRICT]

MINIMUM_KEY_LENGTH = 128
STRICT_KEY_LENGTH = 256

# The strength CRY-11 demands when no baseline states one: NIST's 112-bit floor, which
# 2048-bit MODP is the smallest common group to meet.
DEFAULT_DH_SECURITY_BITS = 112

# Transform IDs. Named rather than inlined so a rule reads as what it checks.
DH_MODP_768 = 1
DH_MODP_1024 = 2
DH_MODP_1536 = 5

ENCR_DES_IDS = frozenset({1, 2})  # DES_IV64, DES
ENCR_3DES_ID = 3
INTEG_NONE_ID = 0
INTEG_MD5_ID = 1
INTEG_SHA1_ID = 2

# Encryption transforms whose name marks them as CBC mode. AEAD ciphers carry their
# own integrity, so "no integrity transform" is correct for them and alarming for CBC.
CBC_MARKER = "_CBC"
AEAD_MARKERS = ("_GCM", "_CCM", "CHACHA20")


def _describe_selection(tunnel: Tunnel, proposal: Proposal) -> str:
    """Say whether this proposal was the one selected, or that it cannot be known."""
    if tunnel.negotiation is None:
        return "selection unknown (no negotiation captured)"
    accepted = tunnel.negotiation.was_accepted(proposal)
    if accepted is None:
        return "selection unknown (the responder's reply was not captured)"
    return "selected in this session" if accepted else "not selected in this session"


def _evidence_for(tunnel: Tunnel, matches: list[tuple[int, Proposal, str]], total: int) -> str:
    """Build the evidence string: what matched, where, and whether it was chosen."""
    parts = [
        f"{label} offered in proposal {index} of {total}, {_describe_selection(tunnel, proposal)}"
        for index, proposal, label in matches
    ]
    return "; ".join(parts)


@dataclass(frozen=True)
class ProposalRule:
    """A rule that inspects each offered proposal in turn.

    Declarative because ten near-identical rules written out longhand would differ from
    each other by accident, and a rule that silently checks the wrong transform type is
    indistinguishable from one that found nothing.
    """

    id: str
    title: str
    severity: Severity
    standard_ref: str
    remediation_hint: str
    match: Callable[[Proposal], list[str]]
    attack_technique: str | None = None
    baselines: list[str] = field(default_factory=lambda: [DEFAULT_BASELINE])
    matcher_factory: Callable[[int], Callable[[Proposal], list[str]]] | None = None
    threshold_field: str | None = None
    """Which :class:`Minimums` field parameterises this rule, if any."""

    def bind(self, baseline: Baseline) -> ProposalRule:
        """Return this rule with its threshold taken from the baseline.

        "Key shorter than the minimum" is one check per authority, not one rule per
        authority: CNSA wants 256 bits and NIST wants 128. Writing both as separate
        rules would mean two IDs, two findings and two remediation lines for one
        problem.

        A baseline that omits the threshold leaves the rule's own default in place.
        Omitted is not zero — a policy that forgets to state a minimum must not
        silently switch the check off.
        """
        if self.matcher_factory is None or self.threshold_field is None:
            return self
        value = getattr(baseline.minimums, self.threshold_field, None)
        if value is None:
            return self
        return replace(self, match=self.matcher_factory(value))

    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None:
            return None
        proposals = tunnel.ike.proposals_offered
        if not proposals:
            return None

        matches: list[tuple[int, Proposal, str]] = []
        for index, proposal in enumerate(proposals, start=1):
            for label in self.match(proposal):
                matches.append((index, proposal, label))
        if not matches:
            return None

        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            evidence=_evidence_for(tunnel, matches, len(proposals)),
            standard_ref=self.standard_ref,
            attack_technique=self.attack_technique,
            remediation_hint=self.remediation_hint,
        )


def _transforms_of(proposal: Proposal, kind: TransformType) -> list[Transform]:
    return [t for t in proposal.transforms if t.type == kind]


def _match_dh_group(group_id: int) -> Callable[[Proposal], list[str]]:
    def matcher(proposal: Proposal) -> list[str]:
        return [
            transform.name
            for transform in _transforms_of(proposal, TransformType.DH)
            if transform.id == group_id
        ]

    return matcher


def _match_encryption(ids: frozenset[int]) -> Callable[[Proposal], list[str]]:
    def matcher(proposal: Proposal) -> list[str]:
        return [
            transform.name
            for transform in _transforms_of(proposal, TransformType.ENCR)
            if transform.id in ids
        ]

    return matcher


def _match_integrity(integ_id: int) -> Callable[[Proposal], list[str]]:
    def matcher(proposal: Proposal) -> list[str]:
        return [
            transform.name
            for transform in _transforms_of(proposal, TransformType.INTEG)
            if transform.id == integ_id
        ]

    return matcher


def _is_aead(transform: Transform) -> bool:
    return any(marker in transform.name for marker in AEAD_MARKERS)


def _match_cbc_without_integrity(proposal: Proposal) -> list[str]:
    """CBC encryption with no integrity protection.

    Unauthenticated CBC is not a weak configuration, it is a broken one: without
    integrity an attacker can modify ciphertext and use the peer's error behaviour as a
    decryption oracle. AEAD ciphers are exempt because they carry integrity internally,
    and flagging them would be a false positive on the strongest option available.
    """
    encryption = _transforms_of(proposal, TransformType.ENCR)
    cbc = [t for t in encryption if CBC_MARKER in t.name and not _is_aead(t)]
    if not cbc:
        return []
    integrity = _transforms_of(proposal, TransformType.INTEG)
    protected = [t for t in integrity if t.id != INTEG_NONE_ID]
    if protected:
        return []
    return [f"{transform.name} with no integrity transform" for transform in cbc]


def _match_short_key(minimum: int) -> Callable[[Proposal], list[str]]:
    def matcher(proposal: Proposal) -> list[str]:
        return [
            f"{transform.name} with a {transform.key_length}-bit key"
            for transform in _transforms_of(proposal, TransformType.ENCR)
            if transform.key_length is not None and transform.key_length < minimum
        ]

    return matcher


CRY_01 = ProposalRule(
    id="CRY-01",
    title="Diffie-Hellman group 1 (768-bit MODP) offered",
    severity=Severity.CRITICAL,
    standard_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Remove group 1 (modp768) from the IKE proposal. Use group 19 (ecp256) or "
        "group 14 (modp2048) at minimum."
    ),
    match=_match_dh_group(DH_MODP_768),
)

CRY_02 = ProposalRule(
    id="CRY-02",
    title="Diffie-Hellman group 2 (1024-bit MODP) offered",
    severity=Severity.CRITICAL,
    standard_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Remove group 2 (modp1024) from the IKE proposal. 1024-bit MODP is within "
        "reach of a precomputation attack against a reused prime; use group 19 "
        "(ecp256) or group 14 (modp2048) at minimum."
    ),
    match=_match_dh_group(DH_MODP_1024),
)

CRY_03 = ProposalRule(
    id="CRY-03",
    title="Diffie-Hellman group 5 (1536-bit MODP) offered",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Replace group 5 (modp1536) with group 14 (modp2048) or group 19 (ecp256). "
        "1536-bit MODP provides under 112 bits of security strength."
    ),
    match=_match_dh_group(DH_MODP_1536),
)

CRY_04 = ProposalRule(
    id="CRY-04",
    title="DES encryption offered",
    severity=Severity.CRITICAL,
    standard_ref="NIST SP 800-131A Rev. 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Remove DES from the ESP and IKE proposals. Its 56-bit key is brute-forceable "
        "in hours on commodity hardware. Use AES-GCM-256 or AES-CBC-256."
    ),
    match=_match_encryption(ENCR_DES_IDS),
)

CRY_05 = ProposalRule(
    id="CRY-05",
    title="3DES encryption offered",
    severity=Severity.CRITICAL,
    standard_ref="NIST SP 800-131A Rev. 2 (disallowed after 2023)",
    attack_technique="T1600.001",
    remediation_hint=(
        "Remove 3DES from the proposals. Its 64-bit block size makes it vulnerable to "
        "birthday-bound collision attacks (Sweet32) on long-lived connections, and "
        "NIST disallowed it for new use after 2023. Use AES-GCM-256."
    ),
    match=_match_encryption(frozenset({ENCR_3DES_ID})),
)

CRY_06 = ProposalRule(
    id="CRY-06",
    title="MD5 integrity offered",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-131A Rev. 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Remove AUTH_HMAC_MD5_96 from the proposals. Use AUTH_HMAC_SHA2_256_128 or stronger."
    ),
    match=_match_integrity(INTEG_MD5_ID),
)

CRY_07 = ProposalRule(
    id="CRY-07",
    title="SHA-1 integrity offered",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-131A Rev. 2",
    attack_technique="T1600.001",
    remediation_hint=("Replace AUTH_HMAC_SHA1_96 with AUTH_HMAC_SHA2_256_128 or stronger."),
    match=_match_integrity(INTEG_SHA1_ID),
)

CRY_08 = ProposalRule(
    id="CRY-08",
    title="CBC encryption offered with no integrity protection",
    severity=Severity.HIGH,
    standard_ref="RFC 7321 section 5",
    attack_technique="T1600.002",
    remediation_hint=(
        "Add an integrity transform to this proposal, or switch to an AEAD cipher such "
        "as AES-GCM. Unauthenticated CBC allows an attacker to modify ciphertext and "
        "use the peer's error behaviour as a decryption oracle."
    ),
    match=_match_cbc_without_integrity,
)

CRY_09 = ProposalRule(
    id="CRY-09",
    title="Encryption key shorter than 128 bits offered",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Raise the key length to at least 128 bits. Below that the cipher provides "
        "less than the minimum acceptable security strength regardless of algorithm."
    ),
    match=_match_short_key(MINIMUM_KEY_LENGTH),
)

CRY_10 = ProposalRule(
    id="CRY-10",
    title="Encryption key shorter than 256 bits where the baseline requires 256",
    severity=Severity.MEDIUM,
    standard_ref="CNSA Suite 1.0",
    remediation_hint=(
        "Raise the key length to 256 bits. AES-128 is not broken; this finding exists "
        "only because the selected baseline requires 256-bit keys."
    ),
    match=_match_short_key(STRICT_KEY_LENGTH),
    matcher_factory=_match_short_key,
    threshold_field="encryption_key_bits",
    baselines=[BASELINE_STRICT],
)


def weaknesses_in(proposal: Proposal) -> list[str]:
    """Every CRY-level weakness in one proposal, named.

    Shared with the IKE rules so that "a weaker proposal was offered" and the CRY
    findings can never disagree about what counts as weak. Two independent notions of
    weakness in one report is a defect an auditor finds immediately.
    """
    found: list[str] = []
    for rule in (CRY_01, CRY_02, CRY_03, CRY_04, CRY_05, CRY_06, CRY_07, CRY_09):
        found.extend(rule.match(proposal))
    found.extend(_match_cbc_without_integrity(proposal))
    return found


def _match_weak_group(minimum_bits: int) -> Callable[[Proposal], list[str]]:
    """DH groups providing less than the baseline's required strength.

    Compared on security strength, never on parameter size or group number. The
    registry is ordered by neither: group 19 (256-bit ECP) has a smaller parameter
    than group 14 (2048-bit MODP) and a lower number than group 21, yet is stronger
    than both group 14 and group 5. An earlier version of this rule compared parameter
    sizes and reported 256-bit ECP as too weak for a 2048-bit floor, which is exactly
    backwards.
    """

    def matcher(proposal: Proposal) -> list[str]:
        found: list[str] = []
        for transform in proposal.transforms:
            if transform.type is None:
                continue
            if not (
                transform.type == TransformType.DH or transform.type.is_additional_key_exchange
            ):
                continue
            bits = dh_security_bits(transform.id)
            if bits is not None and bits < minimum_bits:
                found.append(f"{transform.name} ({bits}-bit security strength)")
        return found

    return matcher


CRY_11 = ProposalRule(
    id="CRY-11",
    title="Diffie-Hellman group weaker than the baseline requires",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2",
    attack_technique="T1600.001",
    remediation_hint=(
        "Raise the Diffie-Hellman group to meet the baseline's required strength. "
        "Unlike the fixed-group rules, this threshold comes from the selected "
        "compliance baseline, so the acceptable group depends on the policy in force."
    ),
    match=_match_weak_group(DEFAULT_DH_SECURITY_BITS),
    matcher_factory=_match_weak_group,
    threshold_field="dh_security_bits",
)


CRYPTO_RULES: list[ProposalRule] = [
    CRY_01,
    CRY_02,
    CRY_03,
    CRY_04,
    CRY_05,
    CRY_06,
    CRY_07,
    CRY_08,
    CRY_09,
    CRY_10,
    CRY_11,
]

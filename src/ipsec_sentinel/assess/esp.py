"""Grade an installed ESP SA, using the rules that already exist.

Step 11.8 made a device's own kernel state reach :func:`config_from_state`, and stopped
at reporting it: ``3des/md5`` printed as neutrally as ``aes256/sha256``. This module
grades it.

**The decisions are reused, not reimplemented.** An installed ESP SA genuinely has an
encryption transform and an integrity transform, so it becomes a real
:class:`~ipsec_sentinel.models.Proposal` and the existing ``ProposalRule.match``
predicates run against it unchanged. A parallel set of "is this 3DES?" checks is exactly
how the IKEv1/IKEv2 registry bug reached this codebase three separate times; there is one
set of names and both paths consult it.

**Two things are deliberately not reused.**

The evidence wording. A CRY-05 read from the wire says "offered in proposal 2 of 2, not
selected"; the offered-versus-selected distinction is the whole point of the crypto rules.
Nothing was offered here — an SA was installed — so the evidence says that instead, and
names the device and the source that reported it.

The rule set. Only rules an ESP SA can actually answer for are run, from an explicit
allowlist. An ESP SA carries no Diffie-Hellman group, no IKE version and no PRF, so
CRY-11 must stay silent rather than fire on an absence. The allowlist is checked against
the registry by a test, because a list naming a rule that was later renamed would quietly
stop checking it.

Findings are deterministic and carry ``confidence = None``: they are read from a device,
not inferred from traffic, which puts them in Section A alongside wire-parsed facts. The
evidence names the source so a reader can tell a kernel's report from a capture — both
are parsed facts and they are not the same evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, Rule, RuleRegistry
from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.assess.rules.crypto import ProposalRule
from ipsec_sentinel.models import (
    Finding,
    ObservedConfig,
    Proposal,
    Transform,
    TransformType,
)

if TYPE_CHECKING:
    from ipsec_sentinel.collect import ESPParameters

# The rules an installed ESP SA can answer for. Everything else needs a key exchange, an
# IKE version or a lifetime, none of which an ESP SA carries.
ESP_PROPOSAL_RULE_IDS: Final[frozenset[str]] = frozenset(
    {
        "CRY-04",  # DES
        "CRY-05",  # 3DES
        "CRY-06",  # MD5
        "CRY-07",  # SHA-1
        "CRY-08",  # CBC with no integrity
        "CRY-09",  # key shorter than the minimum
        "CRY-10",  # key shorter than a strict baseline's minimum
        "CRY-12",  # NULL encryption
    }
)

# The replay rules read a local setting rather than a proposal, so they are evaluated
# from an ObservedConfig rather than through `match`.
ESP_CONFIG_RULE_IDS: Final[frozenset[str]] = frozenset({"SA-03", "SA-04"})

# Canonical ESP names as the transform names the rules already match on, so both paths
# consult one set of names. The transform ids are the IKEv2 encryption registry's, which
# is what `Transform` carries elsewhere in the product.
_ENCRYPTION: Final[dict[str, tuple[str, int]]] = {
    "des": ("ENCR_DES", 2),
    "3des": ("ENCR_3DES", 3),
    "null": ("ENCR_NULL", 11),
    "aes128": ("ENCR_AES_CBC", 12),
    "aes256": ("ENCR_AES_CBC", 12),
    "aes128gcm8": ("ENCR_AES_GCM_8", 18),
    "aes128gcm12": ("ENCR_AES_GCM_12", 19),
    "aes128gcm16": ("ENCR_AES_GCM_16", 20),
    "aes256gcm8": ("ENCR_AES_GCM_8", 18),
    "aes256gcm12": ("ENCR_AES_GCM_12", 19),
    "aes256gcm16": ("ENCR_AES_GCM_16", 20),
}
_INTEGRITY: Final[dict[str, tuple[str, int]]] = {
    "none": ("NONE", 0),
    "md5": ("AUTH_HMAC_MD5_96", 1),
    "sha1": ("AUTH_HMAC_SHA1_96", 2),
    "aesxcbc": ("AUTH_AES_XCBC_96", 5),
    "sha256": ("AUTH_HMAC_SHA2_256_128", 12),
    "sha384": ("AUTH_HMAC_SHA2_384_192", 13),
    "sha512": ("AUTH_HMAC_SHA2_512_256", 14),
}

# Key sizes the canonical name itself states, for a source that did not measure one.
_IMPLIED_KEY_BITS: Final[dict[str, int]] = {
    "des": 64,
    "3des": 192,
    "aes128": 128,
    "aes256": 256,
    "aes128gcm8": 128,
    "aes128gcm12": 128,
    "aes128gcm16": 128,
    "aes256gcm8": 256,
    "aes256gcm12": 256,
    "aes256gcm16": 256,
}


def proposal_from_esp(esp: ESPParameters) -> Proposal | None:
    """The installed SA as a proposal the existing rules can read.

    ``None`` when the cipher has no equivalent transform name, because a rule that
    matches on names cannot judge an algorithm this project has never named. Refused
    rather than approximated, as everywhere else.

    An AEAD cipher contributes no integrity transform: it authenticates internally, and
    inventing one would suppress CRY-08 on exactly the configuration that does not need
    it — while inventing a *missing* one would raise CRY-08 on the strongest option
    available.
    """
    named = _ENCRYPTION.get(esp.encryption)
    if named is None:
        return None
    name, identifier = named

    transforms = [
        Transform(
            type=TransformType.ENCR,
            id=identifier,
            name=name,
            key_length=esp.encryption_keylen or _IMPLIED_KEY_BITS.get(esp.encryption),
        )
    ]
    if not esp.aead and esp.integrity is not None:
        integrity = _INTEGRITY.get(esp.integrity)
        if integrity is None:
            return None
        transforms.append(Transform(type=TransformType.INTEG, id=integrity[1], name=integrity[0]))
    return Proposal(number=1, protocol="ESP", transforms=transforms)


def esp_observed_config(esp: ESPParameters) -> ObservedConfig | None:
    """The replay settings as configuration facts, or ``None`` if none were reported.

    ``sa.py`` notes that the replay window "never appears on the wire in any form" and
    has to come from an operator's document. A kernel read is the same kind of fact from
    a better source: the device itself rather than a description of it.

    A window that was not reported stays ``None``. Not supplied is not zero, and grading
    it as zero would manufacture the most serious anti-replay finding out of a silence.
    """
    if esp.replay_window is None:
        return None
    return ObservedConfig(
        anti_replay_enabled=esp.replay_window > 0,
        replay_window=esp.replay_window,
    )


def _installed_title(title: str) -> str:
    """The rule's title with the wire's verb replaced.

    Rule titles are written for a capture, where an algorithm is *offered* and may or
    may not be selected — the distinction the crypto rules exist to preserve. Nothing was
    offered here, so "3DES encryption offered" would misdescribe a finding whose entire
    evidence is that 3DES is running. The registry keeps its own wording; only this
    path's copy changes.
    """
    return title.replace(" offered", " installed")


def _evidence(esp: ESPParameters, source: str, origin: str, detail: str) -> str:
    where = f"installed on {source}, read from the {origin}"
    suffix = f" (SPI {esp.spi})" if esp.spi else ""
    return f"{detail} — {where}{suffix}"


def assess_esp(
    esp: ESPParameters,
    *,
    source: str,
    origin: str = "kernel",
    baseline: str = DEFAULT_BASELINE,
    registry: RuleRegistry | None = None,
) -> list[Finding]:
    """Grade an installed ESP SA against a baseline.

    ``origin`` is ``"kernel"`` or ``"daemon"`` and travels into the evidence, because
    "the kernel has this installed" and "strongSwan says it installed this" are different
    claims and a reader has to be able to tell them apart.
    """
    registry = registry or default_registry()
    resolved = registry.resolve(baseline)
    selected = {rule.id: rule for rule in registry.select(resolved)}

    findings: list[Finding] = []
    proposal = proposal_from_esp(esp)
    if proposal is not None:
        for rule_id in sorted(ESP_PROPOSAL_RULE_IDS & selected.keys()):
            rule = selected[rule_id]
            if not isinstance(rule, ProposalRule):  # pragma: no cover - shape guard
                continue
            labels = rule.match(proposal)
            if not labels:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=_installed_title(rule.title),
                    severity=rule.severity,
                    evidence=_evidence(esp, source, origin, ", ".join(labels)),
                    standard_ref=rule.standard_ref,
                    attack_technique=rule.attack_technique,
                    remediation_hint=rule.remediation_hint,
                )
            )

    findings += _assess_replay(esp, source, origin, selected)
    return findings


def _assess_replay(
    esp: ESPParameters,
    source: str,
    origin: str,
    selected: Mapping[str, Rule],
) -> list[Finding]:
    """SA-03 and SA-04, from the window the device reported.

    Evaluated here rather than through ``match`` because these rules read a local setting
    rather than a proposal. The thresholds come from the rule objects, so a baseline that
    moves one moves it here too.
    """
    config = esp_observed_config(esp)
    if config is None or config.replay_window is None:
        return []

    findings: list[Finding] = []
    disabled = selected.get("SA-03")
    if disabled is not None and config.anti_replay_enabled is False:
        findings.append(
            Finding(
                rule_id="SA-03",
                title=disabled.title,
                severity=disabled.severity,
                evidence=_evidence(
                    esp, source, origin, "the replay window is 0, so anti-replay is off"
                ),
                standard_ref=disabled.standard_ref,
                attack_technique=getattr(disabled, "attack_technique", None),
                remediation_hint=disabled.remediation_hint,
            )
        )
        # A window of zero is anti-replay being off, which SA-03 already reports. Adding
        # "and the window is small" would be two findings for one setting.
        return findings

    narrow = selected.get("SA-04")
    limit = getattr(narrow, "limit", None)
    if narrow is not None and limit is not None and config.replay_window < limit:
        findings.append(
            Finding(
                rule_id="SA-04",
                title=narrow.title,
                severity=narrow.severity,
                evidence=_evidence(
                    esp,
                    source,
                    origin,
                    f"the replay window is {config.replay_window}, under the {limit} required",
                ),
                standard_ref=narrow.standard_ref,
                attack_technique=getattr(narrow, "attack_technique", None),
                remediation_hint=narrow.remediation_hint,
            )
        )
    return findings

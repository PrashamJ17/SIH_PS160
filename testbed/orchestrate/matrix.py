"""Expand the configuration matrix into a sampled, balanced set of tunnel configs.

A full factorial of the matrix is 576 cells before traffic classes and impairments
multiply it. The goal is not coverage of the product space but coverage of the
*security-relevant spread*, so this samples in strata and anchors on five labelled
configurations that must always appear.

Two balance guarantees are enforced by construction, because they are the guard
against the confound trap described in the master document: every DH group appears at
least once, and **every encryption algorithm appears with at least two different DH
groups**. Without the second, a classifier trained on the resulting corpus could be
reading cipher artifacts while appearing to read traffic shape.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import yaml

from testbed.orchestrate.config_gen import IKEVersion, IPVersion, Mode, TunnelConfig, is_aead

DEFAULT_MATRIX_PATH: Final = Path(__file__).resolve().parents[1] / "configs" / "matrix.yaml"


@dataclass(frozen=True)
class LabelledConfig:
    """A configuration together with the anchor label that pinned it, if any."""

    config: TunnelConfig
    label: str | None = None


class MatrixError(ValueError):
    """The matrix definition is internally inconsistent."""


def load_matrix(path: Path | None = None) -> dict[str, Any]:
    """Load and minimally validate the matrix definition."""
    source = path or DEFAULT_MATRIX_PATH
    data = yaml.safe_load(source.read_text())
    if not isinstance(data, dict):
        raise MatrixError(f"{source} does not contain a mapping")
    required = {"ike_versions", "encryptions", "dh_groups", "pfs", "modes", "sampling"}
    missing = required - set(data)
    if missing:
        raise MatrixError(f"{source} is missing keys: {sorted(missing)}")
    return cast(dict[str, Any], data)


def _integrity_for(encryption: str, integrities: list[str], rng: random.Random) -> str | None:
    """AEAD ciphers take no separate integrity algorithm; everything else needs one."""
    return None if is_aead(encryption) else rng.choice(integrities)


def _prf_for(integrity: str | None, prfs: list[str], rng: random.Random) -> str:
    """Prefer a PRF from the same hash family as the integrity algorithm."""
    if integrity is not None:
        family = f"prf{integrity}"
        if family in prfs:
            return family
    return rng.choice(prfs)


def _dh_allowed_for_version(dh_group: str, ike_version: IKEVersion, ikev2_only: list[str]) -> bool:
    return not (ike_version == "ikev1" and dh_group in ikev2_only)


def _build(
    *,
    encryption: str,
    dh_group: str,
    ike_version: IKEVersion,
    pfs: bool,
    mode: Mode,
    ip_version: IPVersion,
    integrities: list[str],
    prfs: list[str],
    lifetimes: dict[str, list[int]],
    rng: random.Random,
    aggressive: bool = False,
    integrity: str | None = None,
    explicit_integrity: bool = False,
) -> TunnelConfig:
    integ = integrity if explicit_integrity else _integrity_for(encryption, integrities, rng)
    if is_aead(encryption):
        integ = None
    elif integ is None:
        integ = rng.choice(integrities)
    return TunnelConfig(
        ike_version=ike_version,
        encryption=encryption,
        integrity=integ,
        prf=_prf_for(integ, prfs, rng),
        dh_group=dh_group,
        pfs=pfs,
        child_dh_group=dh_group if pfs else None,
        mode=mode,
        ip_version=ip_version,
        ike_lifetime_s=rng.choice(lifetimes["ike_s"]),
        child_lifetime_s=rng.choice(lifetimes["child_s"]),
        aggressive=aggressive,
    )


def _anchors(matrix: dict[str, Any], rng: random.Random) -> list[LabelledConfig]:
    """The five labelled configurations that must always be present."""
    integrities = list(matrix["integrities"])
    prfs = list(matrix["prfs"])
    lifetimes = matrix["lifetimes"]
    out: list[LabelledConfig] = []
    for spec in matrix["sampling"]["must_include"]:
        ike_version = cast(IKEVersion, spec.get("ike_version", "ikev2"))
        config = _build(
            encryption=spec["encryption"],
            dh_group=spec["dh_group"],
            ike_version=ike_version,
            pfs=bool(spec["pfs"]),
            mode=cast(Mode, spec.get("mode", "tunnel")),
            ip_version=cast(IPVersion, spec.get("ip_version", 4)),
            integrities=integrities,
            prfs=prfs,
            lifetimes=lifetimes,
            rng=rng,
            aggressive=bool(spec.get("aggressive", False)),
            integrity=spec.get("integrity"),
            explicit_integrity=True,
        )
        out.append(LabelledConfig(config, spec["label"]))
    return out


def expand_matrix(path: Path | None = None) -> list[LabelledConfig]:
    """Expand the matrix into exactly ``target_count`` distinct configurations.

    The anchors come first, then a coverage pass that guarantees the balance
    properties, then seeded stratified fill. Deduplication is by ``config_id``, and
    the whole expansion is deterministic for a given seed so a sweep can be resumed.
    """
    matrix = load_matrix(path)
    sampling = matrix["sampling"]
    rng = random.Random(sampling.get("seed", 42))

    encryptions: list[str] = [e["name"] for e in matrix["encryptions"]]
    dh_groups: list[str] = list(matrix["dh_groups"])
    ike_versions: list[IKEVersion] = list(matrix["ike_versions"])
    modes: list[Mode] = list(matrix["modes"])
    ip_versions: list[IPVersion] = list(matrix["ip_versions"])
    integrities: list[str] = list(matrix["integrities"])
    prfs: list[str] = list(matrix["prfs"])
    lifetimes: dict[str, list[int]] = matrix["lifetimes"]
    ikev2_only: list[str] = matrix.get("constraints", {}).get("ikev2_only_dh_groups", [])
    target: int = int(sampling["target_count"])

    selected: list[LabelledConfig] = []
    seen: set[str] = set()

    def add(candidate: LabelledConfig) -> bool:
        cid = candidate.config.config_id()
        if cid in seen:
            return False
        seen.add(cid)
        selected.append(candidate)
        return True

    for anchor in _anchors(matrix, rng):
        add(anchor)

    # Coverage pass. Each encryption is paired with two distinct DH groups, offset per
    # encryption so the groups rotate — this is what guarantees the balance property
    # rather than leaving it to chance.
    for index, encryption in enumerate(encryptions):
        for offset in (0, 1):
            group = dh_groups[(index * 2 + offset) % len(dh_groups)]
            version: IKEVersion = (
                "ikev2" if group in ikev2_only else ike_versions[offset % len(ike_versions)]
            )
            add(
                LabelledConfig(
                    _build(
                        encryption=encryption,
                        dh_group=group,
                        ike_version=version,
                        pfs=bool(offset % 2 == 0),
                        mode=modes[offset % len(modes)],
                        ip_version=4,
                        integrities=integrities,
                        prfs=prfs,
                        lifetimes=lifetimes,
                        rng=rng,
                    )
                )
            )

    # Every DH group must appear at least once, including any the rotation missed.
    covered_groups = {lc.config.dh_group for lc in selected}
    for group in dh_groups:
        if group in covered_groups:
            continue
        version = "ikev2" if group in ikev2_only else rng.choice(ike_versions)
        add(
            LabelledConfig(
                _build(
                    encryption=rng.choice(encryptions),
                    dh_group=group,
                    ike_version=version,
                    pfs=True,
                    mode="tunnel",
                    ip_version=4,
                    integrities=integrities,
                    prfs=prfs,
                    lifetimes=lifetimes,
                    rng=rng,
                )
            )
        )

    # Stratified fill to the target. Attempts are bounded so an over-constrained
    # matrix fails loudly rather than looping forever.
    attempts = 0
    max_attempts = target * 200
    while len(selected) < target and attempts < max_attempts:
        attempts += 1
        group = rng.choice(dh_groups)
        version = rng.choice(ike_versions)
        if not _dh_allowed_for_version(group, version, ikev2_only):
            continue
        add(
            LabelledConfig(
                _build(
                    encryption=rng.choice(encryptions),
                    dh_group=group,
                    ike_version=version,
                    pfs=rng.choice(matrix["pfs"]),
                    mode=rng.choice(modes),
                    ip_version=rng.choice(ip_versions),
                    integrities=integrities,
                    prfs=prfs,
                    lifetimes=lifetimes,
                    rng=rng,
                )
            )
        )

    if len(selected) < target:
        raise MatrixError(
            f"could only build {len(selected)} distinct configs for target_count={target}; "
            f"the matrix is too constrained"
        )
    return selected[:target]


def configs(path: Path | None = None) -> list[TunnelConfig]:
    """Just the configurations, without their anchor labels."""
    return [lc.config for lc in expand_matrix(path)]

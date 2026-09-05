#!/usr/bin/env python3
"""Validate and package the generated corpus.

A corpus is only useful if someone else can trust it, so this refuses to package
anything it cannot verify. Every manifest is validated against the schema, every
capture it references must exist and open end to end, and every file is checksummed.
A missing or unreadable capture fails the package with a message naming the file,
rather than producing an index that promises data which is not there.

Emits `INDEX.json` — counts per class, per configuration, per impairment — and
`DATACARD.md`, following the datasheets-for-datasets pattern: what this is, how it was
made, what it is fit for and what it is not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from testbed.orchestrate.capture import CaptureError, verify_pcap  # noqa: E402
from testbed.orchestrate.groundtruth import Manifest  # noqa: E402

DEFAULT_SOURCE: Final = REPO_ROOT / "data" / "raw" / "sweep"
DEFAULT_OUT: Final = REPO_ROOT / "dataset"


class PackagingError(RuntimeError):
    """The corpus could not be validated."""


@dataclass
class CellRecord:
    """One validated cell in the packaged corpus."""

    cell_id: str
    config_id: str
    generator: str
    variant: str
    impairment: str
    negotiation_matched_intent: bool
    encryption: str | None
    dh_group: str | None
    mode: str | None
    ike_version: str | None
    pfs: bool | None
    files: dict[str, dict[str, Any]] = field(default_factory=dict)


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def find_manifests(root: Path) -> list[Path]:
    return sorted(root.rglob("manifest.json"))


def validate_cell(manifest_path: Path) -> CellRecord:
    """Validate one manifest and everything it references.

    Raises with a message naming the file, because "packaging failed" without a path
    is useless when a sweep produced a thousand cells.
    """
    try:
        manifest = Manifest.model_validate_json(manifest_path.read_text())
    except Exception as exc:
        raise PackagingError(
            f"{manifest_path}: manifest does not validate against the schema: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    meta = manifest.capture_meta
    record = CellRecord(
        cell_id=manifest.capture_id,
        config_id=manifest.config_id,
        generator=str(meta.get("generator", "unknown")),
        variant=str(meta.get("variant", "unknown")),
        impairment=str(meta.get("impairment", "unknown")),
        negotiation_matched_intent=manifest.negotiation_matched_intent,
        encryption=(manifest.negotiated_ike.encryption if manifest.negotiated_ike else None),
        dh_group=(manifest.negotiated_ike.dh_group if manifest.negotiated_ike else None),
        mode=(manifest.negotiated_child.mode if manifest.negotiated_child else None),
        ike_version=(manifest.negotiated_ike.ike_version if manifest.negotiated_ike else None),
        pfs=manifest.intent.get("pfs"),
    )

    cell_dir = manifest_path.parent
    for role in ("outer_pcap", "inner_pcap"):
        name = meta.get(role)
        if not name:
            raise PackagingError(f"{manifest_path}: manifest records no {role}")
        capture = cell_dir / str(name)
        if not capture.exists():
            raise PackagingError(
                f"{manifest_path}: references {role} '{name}' which does not exist "
                f"at {capture}"
            )
        try:
            packets = verify_pcap(capture)
        except CaptureError as exc:
            raise PackagingError(f"{manifest_path}: {role} is unusable: {exc}") from exc
        record.files[role] = {
            "file": str(capture.relative_to(cell_dir)),
            "bytes": capture.stat().st_size,
            "packets": packets,
            "sha256": sha256_of(capture),
        }
    record.files["manifest"] = {
        "file": manifest_path.name,
        "bytes": manifest_path.stat().st_size,
        "sha256": sha256_of(manifest_path),
    }
    return record


def build_index(records: list[CellRecord], source: Path) -> dict[str, Any]:
    """Counts per class, per configuration and per impairment."""
    matched = [r for r in records if r.negotiation_matched_intent]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": str(source),
        "cells": len(records),
        "cells_matching_intent": len(matched),
        "cells_not_matching_intent": len(records) - len(matched),
        "counts": {
            "per_class": dict(sorted(Counter(r.generator for r in records).items())),
            "per_variant": dict(sorted(Counter(f"{r.generator}/{r.variant}" for r in records).items())),
            "per_config": dict(sorted(Counter(r.config_id for r in records).items())),
            "per_impairment": dict(sorted(Counter(r.impairment for r in records).items())),
            "per_encryption": dict(sorted(Counter(str(r.encryption) for r in records).items())),
            "per_dh_group": dict(sorted(Counter(str(r.dh_group) for r in records).items())),
            "per_mode": dict(sorted(Counter(str(r.mode) for r in records).items())),
            "per_ike_version": dict(sorted(Counter(str(r.ike_version) for r in records).items())),
        },
        "totals": {
            "outer_packets": sum(r.files["outer_pcap"]["packets"] for r in records),
            "inner_packets": sum(r.files["inner_pcap"]["packets"] for r in records),
            "bytes": sum(
                f["bytes"] for r in records for f in r.files.values()
            ),
        },
        "cells_detail": [
            {
                "cell_id": r.cell_id,
                "config_id": r.config_id,
                "generator": r.generator,
                "variant": r.variant,
                "impairment": r.impairment,
                "negotiation_matched_intent": r.negotiation_matched_intent,
                "encryption": r.encryption,
                "dh_group": r.dh_group,
                "mode": r.mode,
                "ike_version": r.ike_version,
                "files": r.files,
            }
            for r in records
        ],
    }


def check_balance(index: dict[str, Any]) -> list[str]:
    """Report confounds present in the packaged corpus, rather than hiding them."""
    warnings: list[str] = []
    detail = index["cells_detail"]
    pairs: dict[str, set[str]] = {}
    for cell in detail:
        pairs.setdefault(str(cell["generator"]), set()).add(str(cell["encryption"]))
    encryptions = {str(c["encryption"]) for c in detail}
    for generator, seen in sorted(pairs.items()):
        missing = encryptions - seen
        if missing:
            warnings.append(
                f"class '{generator}' never appears with {sorted(missing)} — "
                f"a classifier trained on this corpus could read cipher rather than shape"
            )
    return warnings


def render_datacard(index: dict[str, Any], warnings: list[str]) -> str:
    counts = index["counts"]
    lines = [
        "# Datacard: IPsec Sentinel corpus",
        "",
        f"*Generated {index['generated_at'][:16].replace('T', ' ')} UTC by "
        "`scripts/package_dataset.py`.*",
        "",
        "## What this is",
        "",
        "Packet captures of IPsec tunnels, each labelled with the cryptographic",
        "parameters that were **actually negotiated** and with the application traffic",
        "carried inside. Each cell ships an outer capture (what a passive observer of",
        "the link sees), an inner capture (the cleartext, which supplies the traffic",
        "label) and a manifest recording both intent and reality.",
        "",
        "It exists because no public corpus supplies IPsec crypto labels. See",
        "[`docs/external_dataset_audit.md`](../docs/external_dataset_audit.md) for the",
        "measurement behind that claim, and [`docs/DATASET.md`](../docs/DATASET.md) for",
        "methodology and limitations.",
        "",
        "## Contents",
        "",
        f"* **{index['cells']} cells**, of which **{index['cells_matching_intent']}** "
        "negotiated exactly what was configured",
        f"* {index['totals']['outer_packets']:,} outer packets, "
        f"{index['totals']['inner_packets']:,} inner packets",
        f"* {index['totals']['bytes'] / 1_048_576:.1f} MiB total",
        "",
        "### Cells per traffic class",
        "",
        "| Class | Cells |",
        "|---|---:|",
    ]
    lines += [f"| {k} | {v} |" for k, v in counts["per_class"].items()]
    lines += ["", "### Cells per impairment profile", "", "| Profile | Cells |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in counts["per_impairment"].items()]
    lines += ["", "### Cells per negotiated encryption", "", "| Encryption | Cells |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in counts["per_encryption"].items()]
    lines += ["", "### Cells per negotiated DH group", "", "| DH group | Cells |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in counts["per_dh_group"].items()]

    lines += [
        "",
        "## Labels and how they were obtained",
        "",
        "Labels come from **reality, not intent**: every value is read back from",
        "`swanctl --list-sas` (the daemon) and `ip xfrm state` (the kernel) after the",
        "tunnel established. Each manifest carries `negotiation_matched_intent` and a",
        "list of any divergence; a cell where that flag is false describes something",
        "other than what was configured and must be treated accordingly.",
        "",
        "**No key material is present.** The kernel prints session keys inline and they",
        "are discarded during parsing, never stored. No credential of any kind appears",
        "in this corpus or the repository that produced it.",
        "",
        "## Balance",
        "",
    ]
    if warnings:
        lines += ["**This corpus is confounded:**", ""]
        lines += [f"* {w}" for w in warnings]
        lines += [
            "",
            "Reported rather than suppressed. A model trained on a confounded corpus can",
            "score well while reading the wrong signal entirely.",
        ]
    else:
        lines += [
            "Every traffic class appears with every negotiated encryption algorithm in",
            "this corpus, so application class is not confounded with cipher. That is the",
            "trap this design most needed to avoid: a classifier trained on a confounded",
            "corpus would read cipher artifacts while appearing to read traffic shape.",
        ]

    lines += [
        "",
        "## What it is fit for",
        "",
        "* Training and evaluating in-tunnel traffic classification",
        "* Evaluating tunnel-versus-transport mode inference",
        "* Testing IKE parsers against real negotiations, including IKEv1 Aggressive Mode",
        "* Benchmarking assessment rules against known-bad configurations",
        "",
        "## What it is not fit for",
        "",
        "* **Field deployment claims.** Every tunnel is strongSwan on both ends; no",
        "  Cisco, FortiGate, Juniper or Palo Alto behaviour is represented.",
        "* **Consumer messenger identification.** The messaging class is XMPP used as a",
        "  shape proxy; it is not WhatsApp or Signal and has never seen either.",
        "* **Voice quality or codec work.** The VoIP class is synthetic RTP with no SIP",
        "  signalling and no real codec.",
        "* **Timing analysis of replayed cells.** Replay preserves packet sizes but",
        "  distorts inter-arrival timing.",
        "",
        "The full limitation list is in [`docs/DATASET.md`](../docs/DATASET.md).",
        "",
        "## Integrity",
        "",
        "`INDEX.json` records a SHA-256 for every capture and manifest. Packaging",
        "refuses to proceed if any referenced capture is missing or does not read end",
        "to end, so an index never promises data that is not there.",
        "",
    ]
    return "\n".join(lines)


def package(source: Path, out_dir: Path) -> dict[str, Any]:
    manifests = find_manifests(source)
    if not manifests:
        raise PackagingError(
            f"no manifests found under {source}; run a sweep first with "
            f"testbed.orchestrate.sweep"
        )
    records = [validate_cell(path) for path in manifests]
    index = build_index(records, source)
    warnings = check_balance(index)
    index["balance_warnings"] = warnings

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "INDEX.json").write_text(json.dumps(index, indent=2))
    (out_dir / "DATACARD.md").write_text(render_datacard(index, warnings))
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and package the corpus.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    try:
        index = package(args.source, args.out)
    except PackagingError as exc:
        print(f"packaging failed: {exc}", file=sys.stderr)
        return 1

    print(f"cells packaged      : {index['cells']}")
    print(f"matching intent     : {index['cells_matching_intent']}")
    print(f"outer/inner packets : {index['totals']['outer_packets']:,} / "
          f"{index['totals']['inner_packets']:,}")
    for warning in index["balance_warnings"]:
        print(f"balance warning     : {warning}")
    print(f"index               : {args.out / 'INDEX.json'}")
    print(f"datacard            : {args.out / 'DATACARD.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

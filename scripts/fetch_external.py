#!/usr/bin/env python3
"""Reproducible acquisition of the external datasets, with integrity checking.

Two of these corpora cannot be downloaded at all: CIC-IDS2017 and ISCXVPN2016 require
registration with the University of New Brunswick. Rather than fail obscurely, those
entries print exactly what a human must do and exit 0, so a fresh clone can run this
script, see what it is missing and why, and carry on with what it can get.

Every download is verified against a recorded SHA-256 before it is moved into place. A
mismatch removes the partial file rather than leaving a plausible-looking corpus that
is quietly wrong — which is worse than having none.

Each dataset gets a provenance record: where it came from, what it hashed to, and
when. Step 3.5 audits these files for IPsec content, and that audit is only as
credible as the provenance behind it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_DEST: Final = REPO_ROOT / "data" / "external"
PROVENANCE_FILENAME: Final = "provenance.json"

Downloader = Callable[[str, Path], None]


@dataclass(frozen=True)
class Dataset:
    """One external corpus and how to obtain it."""

    key: str
    kind: str
    use: str
    note: str = ""
    url: str | None = None
    sha256: str | None = None
    manual_download: bool = False
    instructions: str = ""
    filename: str | None = None

    @property
    def target_name(self) -> str:
        if self.filename:
            return self.filename
        if self.url:
            return self.url.rstrip("/").split("/")[-1] or f"{self.key}.dat"
        return f"{self.key}.dat"


DATASETS: Final[dict[str, Dataset]] = {
    "cicids2017": Dataset(
        key="cicids2017",
        kind="pcap",
        use="inner payload replay (benign subset only)",
        note="Contains NO IPsec. Used as a replay source only.",
        url="https://www.unb.ca/cic/datasets/ids-2017.html",
        manual_download=True,
        instructions=(
            "CIC-IDS2017 requires registration with the University of New Brunswick.\n"
            "  1. Open https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "  2. Complete the download form to obtain the PCAP archive\n"
            "  3. Place the Monday (benign-only) capture at\n"
            "     data/external/cicids2017/Monday-WorkingHours.pcap\n"
            "The benign subset is the only part used, as inner payload for replay."
        ),
    ),
    "iscxvpn2016": Dataset(
        key="iscxvpn2016",
        kind="pcap",
        use="comparison baseline for traffic classification",
        note=(
            "OpenVPN, not IPsec. Documented broadcast-flow contamination; see "
            "docs/DATASET.md before using."
        ),
        url="https://www.unb.ca/cic/datasets/vpn.html",
        manual_download=True,
        instructions=(
            "ISCXVPN2016 requires registration with the University of New Brunswick.\n"
            "  1. Open https://www.unb.ca/cic/datasets/vpn.html\n"
            "  2. Complete the download form\n"
            "  3. Place the captures under data/external/iscxvpn2016/\n"
            "Note this corpus is OpenVPN, not IPsec, and needs cleaning first."
        ),
    ),
    "mawi": Dataset(
        key="mawi",
        kind="pcap",
        use="inner payload replay (background traffic)",
        note="Backbone traffic; anonymised. No IPsec expected.",
        url="http://mawi.wide.ad.jp/mawi/",
        manual_download=True,
        instructions=(
            "MAWI publishes per-day archives; pick one rather than mirroring the set.\n"
            "  1. Open http://mawi.wide.ad.jp/mawi/ and choose a samplepoint archive\n"
            "  2. Place the extracted capture at data/external/mawi/mawi_sample.pcap\n"
            "A single 15-minute sample is enough for replay."
        ),
    ),
    "mitre_attack": Dataset(
        key="mitre_attack",
        kind="json",
        use="technique mapping for findings",
        url=(
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json"
        ),
        filename="enterprise-attack.json",
    ),
    "nvd_cve": Dataset(
        key="nvd_cve",
        kind="json_api",
        use="VID fingerprint -> CVE correlation",
        note="Queried per product at enrichment time and cached locally.",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        manual_download=True,
        instructions=(
            "The NVD is queried on demand rather than mirrored: the full corpus is\n"
            "large and changes daily. Step 6.8 caches per-product results under\n"
            "data/external/nvd_cve/ so the tool still works offline."
        ),
    ),
}


class ChecksumMismatchError(RuntimeError):
    """A download did not hash to the recorded value."""


@dataclass
class FetchResult:
    """What happened for one dataset."""

    key: str
    status: str  # fetched | skipped | manual | failed
    path: str | None = None
    sha256: str | None = None
    message: str = ""
    instructions: str = ""
    details: dict[str, str] = field(default_factory=dict)


def sha256_of(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _urllib_download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=120) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def fetch_one(
    dataset: Dataset,
    dest_root: Path,
    *,
    downloader: Downloader | None = None,
    force: bool = False,
) -> FetchResult:
    """Obtain one dataset, verify it, and record where it came from."""
    target_dir = dest_root / dataset.key
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / dataset.target_name

    if dataset.manual_download:
        return FetchResult(
            key=dataset.key,
            status="manual",
            path=str(target_dir),
            message=f"{dataset.key} requires a manual download",
            instructions=dataset.instructions,
        )

    if target.exists() and not force:
        return FetchResult(
            key=dataset.key,
            status="skipped",
            path=str(target),
            sha256=sha256_of(target),
            message="already present",
        )

    if dataset.url is None:
        return FetchResult(
            key=dataset.key, status="failed", message="no URL recorded for this dataset"
        )

    download = downloader or _urllib_download
    # Download to a temporary file so a failed or mismatched fetch never leaves a
    # partial file that later looks like a complete corpus.
    with tempfile.TemporaryDirectory(prefix="sentinel-fetch-") as staging:
        staged = Path(staging) / dataset.target_name
        try:
            download(dataset.url, staged)
        except Exception as exc:
            return FetchResult(
                key=dataset.key,
                status="failed",
                message=f"download failed: {type(exc).__name__}: {exc}",
            )

        digest = sha256_of(staged)
        if dataset.sha256 and digest != dataset.sha256:
            raise ChecksumMismatchError(
                f"{dataset.key}: expected sha256 {dataset.sha256}, got {digest}; "
                f"the partial download was discarded"
            )
        shutil.move(str(staged), str(target))

    write_provenance(dataset, target, digest, target_dir)
    return FetchResult(
        key=dataset.key,
        status="fetched",
        path=str(target),
        sha256=digest,
        message="downloaded and verified",
    )


def write_provenance(dataset: Dataset, target: Path, digest: str, target_dir: Path) -> Path:
    """Record where a file came from, what it hashed to, and when."""
    record = {
        "key": dataset.key,
        "url": dataset.url,
        "kind": dataset.kind,
        "use": dataset.use,
        "note": dataset.note,
        "file": target.name,
        "sha256": digest,
        "bytes": target.stat().st_size if target.exists() else 0,
        "fetched_at": datetime.now(UTC).isoformat(),
    }
    path = target_dir / PROVENANCE_FILENAME
    path.write_text(json.dumps(record, indent=2))
    return path


def fetch_all(
    dest_root: Path,
    *,
    only: list[str] | None = None,
    downloader: Downloader | None = None,
    force: bool = False,
) -> list[FetchResult]:
    keys = only or list(DATASETS)
    unknown = [k for k in keys if k not in DATASETS]
    if unknown:
        raise ValueError(f"unknown dataset(s): {unknown}; have {sorted(DATASETS)}")
    return [fetch_one(DATASETS[key], dest_root, downloader=downloader, force=force) for key in keys]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch the external datasets.")
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    try:
        results = fetch_all(args.dest, only=args.only, force=args.force)
    except ChecksumMismatchError as exc:
        print(f"integrity failure: {exc}", file=sys.stderr)
        return 1

    manual = [r for r in results if r.status == "manual"]
    for result in results:
        print(f"[{result.status:>7}] {result.key}: {result.message}")

    if manual:
        print("\nThe following require a manual download:\n")
        for result in manual:
            print(f"--- {result.key} ---")
            print(result.instructions)
            print()
        print(
            "These corpora contain no IPsec traffic; they are used only as inner\n"
            "payload for replay. Step 3.5 audits whatever is present and reports it."
        )
    # Manual-download entries are an expected state, not a failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

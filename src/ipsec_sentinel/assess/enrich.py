"""Enrichment: ATT&CK technique names, vendor fingerprints, and cached CVE lookups.

Enrichment turns a finding into something an analyst can act on without leaving the
report — "T1040" becomes "Network Sniffing" with a link, and an opaque vendor ID
becomes "this is a Cisco device". None of it changes what was found; all of it changes
how quickly the finding can be understood.

**Everything here works offline, and that is a requirement rather than a nicety.** This
tool is pointed at captures from networks under investigation, which is exactly the
situation in which a host may have no outbound access — and a security tool that
degrades into an error page when it cannot reach the internet is a tool that fails when
it is needed. Every lookup therefore reads from local data, network access is opt-in
and off by default, and a missing corpus yields an empty result rather than an
exception.

The ATT&CK catalogue is a 48 MB STIX bundle. Parsing it per lookup would make
enrichment the slowest part of a report, so a compact index is built once and cached;
the cache is written atomically, because a cache truncated by an interrupt is worse
than no cache — it fails on the next read in a way that looks like corruption rather
than absence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from ipsec_sentinel.logging import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
EXTERNAL_DIR = REPO_ROOT / "data" / "external"
ATTACK_BUNDLE = EXTERNAL_DIR / "mitre_attack" / "enterprise-attack.json"
ATTACK_INDEX = EXTERNAL_DIR / "mitre_attack" / "technique_index.json"
CVE_CACHE = EXTERNAL_DIR / "nvd_cve" / "cve_cache.json"

ATTACK_SOURCE: Final = "mitre-attack"


@dataclass(frozen=True)
class AttackTechnique:
    """One ATT&CK technique, resolved."""

    technique_id: str
    name: str
    url: str


@dataclass(frozen=True)
class VendorFingerprint:
    """What a vendor ID payload identifies."""

    vendor_id: str
    product: str
    detail: str | None = None
    """A version or capability where the payload encodes one."""


@dataclass(frozen=True)
class CVEReference:
    """One CVE, from the local cache."""

    cve_id: str
    summary: str
    severity: str | None = None
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            object.__setattr__(self, "url", f"https://nvd.nist.gov/vuln/detail/{self.cve_id}")


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------


def _build_attack_index(bundle: Path) -> dict[str, dict[str, str]]:
    """Reduce the STIX bundle to {technique ID: {name, url}}."""
    data = json.loads(bundle.read_text())
    index: dict[str, dict[str, str]] = {}
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") != ATTACK_SOURCE:
                continue
            technique_id = ref.get("external_id")
            if not technique_id:
                continue
            index[technique_id] = {
                "name": obj.get("name", technique_id),
                "url": ref.get("url", f"https://attack.mitre.org/techniques/{technique_id}"),
            }
    return index


def write_json_atomically(path: Path, payload: Any) -> None:
    """Write JSON so an interrupt leaves the old file, never a truncated one.

    A half-written cache is worse than none: the next read fails as corruption rather
    than absence, and the caller cannot tell the difference without inspecting it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True))
    temporary.replace(path)


@lru_cache(maxsize=1)
def load_attack_index(
    bundle: Path | None = None, index_path: Path | None = None
) -> dict[str, dict[str, str]]:
    """The technique index, from cache when possible, rebuilt when not.

    Returns an empty index rather than raising when the bundle is absent. A report that
    cannot expand technique IDs is still a useful report; one that refuses to render
    because a reference corpus is missing is not.
    """
    bundle = bundle or ATTACK_BUNDLE
    index_path = index_path or ATTACK_INDEX

    if index_path.exists():
        try:
            cached = json.loads(index_path.read_text())
            if isinstance(cached, dict):
                return cached
        except (OSError, json.JSONDecodeError):
            logger.warning("attack_index_unreadable", extra={"path": str(index_path)})

    if not bundle.exists():
        logger.info("attack_bundle_absent", extra={"path": str(bundle)})
        return {}

    try:
        index = _build_attack_index(bundle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("attack_bundle_unreadable", extra={"error": str(exc)})
        return {}

    try:
        write_json_atomically(index_path, index)
    except OSError as exc:  # pragma: no cover - a read-only corpus is still usable
        logger.warning("attack_index_unwritable", extra={"error": str(exc)})
    return index


def technique(technique_id: str) -> AttackTechnique | None:
    """Resolve an ATT&CK technique ID, or ``None`` if it is unknown."""
    if not technique_id:
        return None
    entry = load_attack_index().get(technique_id)
    if entry is None:
        return None
    return AttackTechnique(technique_id=technique_id, name=entry["name"], url=entry["url"])


# ---------------------------------------------------------------------------
# Vendor ID fingerprints
# ---------------------------------------------------------------------------

# Seeded from the publicly documented vendor ID values that ike-scan and the RFCs
# describe. Deliberately not exhaustive: a fingerprint table that guesses produces
# confident misattribution, which in an assessment is worse than saying nothing. An
# unrecognised ID returns None and OPS-01 still reports any cleartext it contained.
VENDOR_FINGERPRINTS: Final[dict[str, VendorFingerprint]] = {
    "afcad71368a1f1c96b8696fc77570100": VendorFingerprint(
        "afcad71368a1f1c96b8696fc77570100", "Dead Peer Detection", "RFC 3706"
    ),
    "4a131c81070358455c5728f20e95452f": VendorFingerprint(
        "4a131c81070358455c5728f20e95452f", "NAT traversal", "RFC 3947"
    ),
    "90cb80913ebb696e086381b5ec427b1f": VendorFingerprint(
        "90cb80913ebb696e086381b5ec427b1f", "NAT traversal", "draft-ietf-ipsec-nat-t-ike-02"
    ),
    "cd60464335df21f87cfdb2fc68b6a448": VendorFingerprint(
        "cd60464335df21f87cfdb2fc68b6a448", "NAT traversal", "draft-ietf-ipsec-nat-t-ike-02"
    ),
    "4485152d18b6bbcd0be8a8469579ddcc": VendorFingerprint(
        "4485152d18b6bbcd0be8a8469579ddcc", "NAT traversal", "draft-ietf-ipsec-nat-t-ike-00"
    ),
    "1e2b516905991c7d7c96fcbfb587e461": VendorFingerprint(
        "1e2b516905991c7d7c96fcbfb587e461", "NAT traversal", "draft-ietf-ipsec-nat-t-ike-03"
    ),
    "12f5f28c457168a9702d9fe274cc0100": VendorFingerprint(
        "12f5f28c457168a9702d9fe274cc0100", "Cisco Unity", None
    ),
}

# Vendor IDs whose leading bytes identify the product and whose tail encodes a version.
VENDOR_PREFIXES: Final[dict[str, str]] = {
    "4048b7d56ebce885": "Microsoft Windows (MS NT5 ISAKMPOAKLEY)",
    "09002689dfd6b712": "XAUTH",
    "afcad71368a1f1c9": "Dead Peer Detection",
}


def identify_vendor(vendor_id: str) -> VendorFingerprint | None:
    """Identify a vendor ID payload, or ``None`` when it is not recognised.

    Never raises, whatever the input: a vendor ID is attacker-controlled bytes, and a
    fingerprint lookup that can be crashed by a malformed one is a liability.
    """
    if not vendor_id:
        return None
    normalised = vendor_id.strip().lower()

    exact = VENDOR_FINGERPRINTS.get(normalised)
    if exact is not None:
        return exact

    for prefix, product in VENDOR_PREFIXES.items():
        if normalised.startswith(prefix):
            suffix = normalised[len(prefix) :]
            return VendorFingerprint(
                vendor_id=normalised,
                product=product,
                detail=f"version bytes {suffix}" if suffix else None,
            )

    # Some implementations simply write their name. That is a fingerprint too, and a
    # better one than a hash, because it carries the version.
    try:
        decoded = bytes.fromhex(normalised).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    if decoded.isprintable() and any(char.isalpha() for char in decoded):
        return VendorFingerprint(
            vendor_id=normalised, product=decoded.strip(), detail="cleartext vendor ID"
        )
    return None


# ---------------------------------------------------------------------------
# CVE lookup
# ---------------------------------------------------------------------------


def _cache_key(product: str, version: str | None) -> str:
    return f"{product.strip().lower()}|{(version or '').strip().lower()}"


def load_cve_cache(path: Path | None = None) -> dict[str, list[dict[str, Any]]]:
    """The local CVE cache, or an empty mapping when there is none."""
    path = path or CVE_CACHE
    if not path.exists():
        return {}
    try:
        cached = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("cve_cache_unreadable", extra={"path": str(path)})
        return {}
    return cached if isinstance(cached, dict) else {}


def lookup_cves(
    product: str, version: str | None = None, *, cache_path: Path | None = None
) -> list[CVEReference]:
    """CVEs for a product, from the local cache only.

    There is deliberately no network path here. The tool runs on hosts that may have no
    outbound access, and a lookup that sometimes reaches NVD and sometimes does not
    would make reports non-reproducible — two runs over the same capture would differ
    for reasons unrelated to the capture. Populating the cache is a separate, explicit
    operation.

    A cache miss is an empty list, never an error: "no CVEs are cached for this
    product" and "this product has no CVEs" are different statements, and the caller is
    given the data to tell them apart rather than an exception.
    """
    cache = load_cve_cache(cache_path)
    entries = cache.get(_cache_key(product, version))
    if entries is None and version is not None:
        entries = cache.get(_cache_key(product, None))
    if not entries:
        return []
    references: list[CVEReference] = []
    for entry in entries:
        if not isinstance(entry, dict) or "cve_id" not in entry:
            continue
        references.append(
            CVEReference(
                cve_id=str(entry["cve_id"]),
                summary=str(entry.get("summary", "")),
                severity=entry.get("severity"),
                url=str(entry.get("url", "")),
            )
        )
    return references


def store_cves(
    product: str,
    version: str | None,
    references: list[CVEReference],
    *,
    cache_path: Path | None = None,
) -> None:
    """Add entries to the CVE cache, written atomically."""
    path = cache_path or CVE_CACHE
    cache = load_cve_cache(path)
    cache[_cache_key(product, version)] = [
        {
            "cve_id": ref.cve_id,
            "summary": ref.summary,
            "severity": ref.severity,
            "url": ref.url,
        }
        for ref in references
    ]
    write_json_atomically(path, cache)


@dataclass(frozen=True)
class CorpusStatus:
    """Which reference corpora were readable when a report was built.

    A report with no ATT&CK technique names and no vendor CVEs looks exactly the same
    whether the corpora were absent or the findings genuinely mapped to nothing. On an
    air-gapped host the first is the normal case, so without this a degraded run reads
    as a clean one — the failure mode this whole module exists to avoid.
    """

    attack_techniques: int
    cve_cache_entries: int

    @property
    def degraded(self) -> bool:
        return self.attack_techniques == 0 or self.cve_cache_entries == 0

    @property
    def note(self) -> str | None:
        """A sentence for the report, or ``None`` when nothing is missing."""
        missing: list[str] = []
        if self.attack_techniques == 0:
            missing.append(
                "ATT&CK technique names are unavailable — the MITRE bundle is not "
                "present on this host, so technique IDs appear unexpanded"
            )
        if self.cve_cache_entries == 0:
            missing.append(
                "vendor CVE enrichment is unavailable — no local CVE cache was found, "
                "so this report lists no product-specific advisories"
            )
        if not missing:
            return None
        return (
            "Enrichment ran with reduced reference data: "
            + "; ".join(missing)
            + ". The protocol CVEs in the threat matrix are built in and unaffected, "
            "and every finding in this report was produced without them."
        )


def corpus_status(
    *, index_path: Path | None = None, cache_path: Path | None = None
) -> CorpusStatus:
    """Count what enrichment has to work with, without fetching anything.

    Reads the caches directly rather than calling :func:`load_attack_index`, which would
    rebuild a 48 MB bundle just to answer "is it there?".
    """
    index_path = index_path or ATTACK_INDEX
    return CorpusStatus(
        attack_techniques=len(_read_json_mapping(index_path)),
        cve_cache_entries=len(load_cve_cache(cache_path)),
    )


def _read_json_mapping(path: Path) -> dict[str, Any]:
    """A JSON object from disk, or an empty one when absent or unreadable."""
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("corpus_unreadable", extra={"path": str(path)})
        return {}
    return loaded if isinstance(loaded, dict) else {}

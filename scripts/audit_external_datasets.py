#!/usr/bin/env python3
"""Audit the problem statement's named datasets for IPsec content.

The problem statement points at CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13,
CICIoT2023, LANL and DARPA. Every one of them was built for intrusion detection. The
claim this script tests is that none contains the traffic an IPsec analyser needs:
no IKE negotiations, no ESP, no AH — and therefore no cipher, DH-group, mode or PFS
labels either, since those exist only inside a negotiation.

The point is to turn an assertion into a reproducible measurement. "We read the brief
and the datasets do not fit it" is an opinion; a counter run over the files, with its
method stated, is evidence.

**The positive control is not decoration.** A script reporting zero IPsec packets
proves nothing unless it can be shown to find IPsec when IPsec is there. Every run
therefore audits this project's own captures first, and a run whose control finds
nothing declares itself invalid rather than reporting a flattering zero.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ipsec_sentinel.data.pcap_scan import ScanResult, find_captures, scan_capture  # noqa: E402

DEFAULT_EXTERNAL: Final = REPO_ROOT / "data" / "external"
DEFAULT_CONTROL: Final = REPO_ROOT / "data" / "raw"
DEFAULT_REPORT: Final = REPO_ROOT / "docs" / "external_dataset_audit.md"
DEFAULT_JSON: Final = REPO_ROOT / "reports" / "external_dataset_audit.json"

# The corpora the problem statement names, with why each was examined.
NAMED_DATASETS: Final[dict[str, str]] = {
    "cicids2017": "CIC-IDS2017 — benign + attack traffic, HTTP/HTTPS/FTP/SSH/SMTP only",
    "csecicids2018": "CSE-CIC-IDS2018 — extension of 2017, same methodology",
    "unswnb15": "UNSW-NB15 — IXIA-generated, nine attack families",
    "ctu13": "CTU-13 — thirteen botnet capture scenarios",
    "ciciot2023": "CICIoT2023 — IoT DDoS/DoS/Mirai/recon/spoofing",
    "lanl": "LANL — authentication logs, not packet captures",
    "darpa": "DARPA — legacy 1998-2000 intrusion captures",
    "iscxvpn2016": "ISCXVPN2016 — closest public VPN corpus, but OpenVPN not IPsec",
    "mawi": "MAWI — backbone background traffic",
}


@dataclass
class DatasetAudit:
    """The verdict for one named corpus."""

    key: str
    description: str
    present: bool
    files_scanned: int = 0
    total_packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    esp_over_udp_packets: int = 0
    unreadable_files: int = 0
    files: list[dict[str, object]] = field(default_factory=list)

    @property
    def ipsec_packets(self) -> int:
        return self.ike_packets + self.esp_packets + self.ah_packets


def audit_directory(key: str, description: str, root: Path) -> DatasetAudit:
    captures = find_captures(root)
    audit = DatasetAudit(key=key, description=description, present=bool(captures))
    for capture in captures:
        result = scan_capture(capture)
        audit.files_scanned += 1
        if not result.readable:
            audit.unreadable_files += 1
        audit.total_packets += result.total_packets
        audit.ike_packets += result.ike_packets
        audit.esp_packets += result.esp_packets
        audit.ah_packets += result.ah_packets
        audit.esp_over_udp_packets += result.esp_over_udp_packets
        audit.files.append(
            {
                "file": str(capture.relative_to(root)) if root in capture.parents else str(capture),
                "readable": result.readable,
                "error": result.error,
                "packets": result.total_packets,
                "ike": result.ike_packets,
                "esp": result.esp_packets,
                "ah": result.ah_packets,
            }
        )
    return audit


def run_control(root: Path, limit: int = 24) -> list[ScanResult]:
    """Scan this project's own captures, to prove the counter can find IPsec.

    Both an IKE-bearing and an ESP-bearing capture must appear, so the sample is not
    truncated at an arbitrary few files: not every capture here contains a handshake,
    because some were taken after the tunnel was already established.

    An inner (plaintext) capture is included deliberately as a negative control — the
    same scanner must report zero for traffic that genuinely has no IPsec in it.
    """
    outer = sorted(root.rglob("capture_outer.pcap"))[:limit]
    inner = sorted(root.rglob("capture_inner.pcap"))[:2]
    return [scan_capture(p) for p in (*outer, *inner)]


def control_is_valid(results: list[ScanResult]) -> bool:
    """The control passes only if IKE *and* ESP were both found somewhere.

    Requiring both matters: a scanner that counted ESP but silently missed every IKE
    negotiation would still report a confident zero for the external corpora, and the
    conclusion drawn from it would be worthless.
    """
    return (
        any(r.ike_packets > 0 for r in results)
        and any(r.esp_packets > 0 for r in results)
    )


def render_report(
    audits: list[DatasetAudit], control: list[ScanResult], control_ok: bool
) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    present = [a for a in audits if a.present]
    absent = [a for a in audits if not a.present]
    total_ipsec = sum(a.ipsec_packets for a in present)

    lines: list[str] = [
        "# External dataset audit: IPsec content",
        "",
        f"*Generated {generated} by `scripts/audit_external_datasets.py`.*",
        "",
        "## The claim under test",
        "",
        "The problem statement points at CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15,",
        "CTU-13, CICIoT2023, LANL and DARPA. Every one was built for intrusion",
        "detection. This audit tests whether any of them contains what an IPsec",
        "analyser actually needs:",
        "",
        "* **IKE negotiations** — UDP 500, or UDP 4500 preceded by the non-ESP marker",
        "* **ESP** — IP protocol 50",
        "* **AH** — IP protocol 51",
        "",
        "Without a negotiation there is also no label for cipher, DH group, mode or",
        "PFS, because those values exist only inside one.",
        "",
        "## Method",
        "",
        "Each capture is walked record by record. The link layer is stripped",
        "(Ethernet, VLAN-tagged Ethernet, Linux SLL, raw IP or BSD loopback), the IP",
        "protocol number is read, and UDP source and destination ports are compared",
        "against 500 and 4500. On 4500 the four-byte non-ESP marker is checked, so",
        "ESP-over-UDP is counted separately and never inflates the IKE total.",
        "",
        "No sampling: every packet in every file present is examined.",
        "",
        "## Positive control",
        "",
        "A counter that reports zero proves nothing until it is shown to find IPsec",
        "when IPsec is present. Before auditing anything else, the same code is run",
        "over captures produced by this project's own testbed, which are known to",
        "contain IKE and ESP.",
        "",
        "| Capture | Packets | IKE | ESP | AH |",
        "|---|---:|---:|---:|---:|",
    ]
    for result in control:
        name = Path(result.path).parent.name + "/" + Path(result.path).name
        lines.append(
            f"| `{name}` | {result.total_packets} | {result.ike_packets} | "
            f"{result.esp_packets} | {result.ah_packets} |"
        )
    lines += [
        "",
        (
            "**Control result: PASS.** The scanner finds both IKE negotiations and ESP "
            "in captures known to contain them, so a zero elsewhere is a property of "
            "that corpus and not of this code."
            if control_ok
            else "**Control result: FAIL.** The scanner did not find IKE and ESP in "
            "captures known to contain both. This audit is therefore INVALID and its "
            "zeros must not be cited."
        ),
        "",
        "## Results",
        "",
    ]

    if present:
        lines += [
            "### Corpora examined",
            "",
            "| Dataset | Files | Packets | IKE | ESP | AH | IPsec total |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for audit in present:
            lines.append(
                f"| {audit.key} | {audit.files_scanned} | {audit.total_packets:,} | "
                f"{audit.ike_packets} | {audit.esp_packets} | {audit.ah_packets} | "
                f"**{audit.ipsec_packets}** |"
            )
        lines += [
            "",
            (
                f"**{total_ipsec} IPsec packets across every corpus examined.**"
                if total_ipsec
                else "**Zero IPsec packets across every corpus examined.** No IKE "
                "negotiation, no ESP, no AH — and therefore no cipher, DH-group, mode "
                "or PFS label anywhere in them."
            ),
            "",
        ]

    if absent:
        lines += [
            "### Corpora not present on this machine",
            "",
            "These were not scanned because the files are not here. CIC-IDS2017 and",
            "ISCXVPN2016 require registration with the University of New Brunswick;",
            "`scripts/fetch_external.py` prints the exact steps. LANL is authentication",
            "logs rather than packet captures, so there is nothing to scan in any case.",
            "",
            "| Dataset | Why it is named |",
            "|---|---|",
        ]
        for audit in absent:
            lines.append(f"| {audit.key} | {audit.description} |")
        lines += [
            "",
            "This audit reports only what it measured. Where a corpus is absent it says",
            "so rather than inferring a zero from the literature.",
            "",
        ]

    lines += [
        "## What follows from this",
        "",
        "1. **No public corpus supplies IPsec crypto labels.** Even a capture that did",
        "   contain ESP would carry no record of the cipher or DH group negotiated, so",
        "   it could not train or evaluate the identification this problem asks for.",
        "2. **Generating the corpus is therefore objective (a), not a workaround.** The",
        "   testbed configures each tunnel and reads back what was actually negotiated,",
        "   which is the only way to obtain ground truth here.",
        "3. **The named datasets are still used, as inner payload.** Their benign",
        "   traffic is real traffic; replayed through our tunnels it supplies authentic",
        "   packet-size and burst structure while our configuration supplies the labels.",
        "   That is the only technically sound use of them for this problem.",
        "",
        "*Reproduce with `python scripts/audit_external_datasets.py`.*",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit external datasets for IPsec content.")
    parser.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--control", type=Path, default=DEFAULT_CONTROL)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    args = parser.parse_args(argv)

    control = run_control(args.control)
    control_ok = control_is_valid(control)

    audits = [
        audit_directory(key, description, args.external / key)
        for key, description in NAMED_DATASETS.items()
    ]

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(audits, control, control_ok))
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(),
                "control_valid": control_ok,
                "control": [asdict(r) for r in control],
                "datasets": [asdict(a) for a in audits],
            },
            indent=2,
        )
    )

    examined = [a for a in audits if a.present]
    total = sum(a.ipsec_packets for a in examined)
    print(f"control: {'PASS' if control_ok else 'FAIL'}")
    print(f"corpora examined: {len(examined)} of {len(audits)}")
    print(f"IPsec packets found in external corpora: {total}")
    print(f"report: {args.report}")
    if not control_ok:
        print(
            "audit INVALID: the positive control failed.\n"
            "The scanner did not find both IKE and ESP in local captures, so a zero "
            "for the external corpora would prove nothing.\n"
            "Produce a known-good capture with:\n"
            "  python -m testbed.orchestrate.single_run --config-label weak",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

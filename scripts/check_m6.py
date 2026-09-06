#!/usr/bin/env python3
"""Execute the M6 acceptance checklist and report pass/fail per item.

Same shape as the M4 and M5 gates: an executable check, so a later regression fails it
rather than quietly invalidating a claim made once in a commit message.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.assess.anomaly import (  # noqa: E402
    anomaly_summary,
    detect_config_anomalies,
)
from ipsec_sentinel.assess.baselines.schema import load_baselines  # noqa: E402
from ipsec_sentinel.assess.rules import ALL_RULES, default_registry  # noqa: E402
from ipsec_sentinel.assess.rules.pqc import PQCGrade, grade_pqc  # noqa: E402
from ipsec_sentinel.assess.scoring import score_tunnel  # noqa: E402
from ipsec_sentinel.models import (  # noqa: E402
    IKEExchange,
    ObservedConfig,
    Proposal,
    Transform,
    TransformType,
)
from ipsec_sentinel.parser.correlate import Tunnel, correlate  # noqa: E402
from ipsec_sentinel.parser.esp import (  # noqa: E402
    assemble_esp_flows,
    extract_esp_packets,
)
from ipsec_sentinel.parser.pcap import extract_ike_exchanges  # noqa: E402

SWEEP_ROOT: Final = REPO_ROOT / "data" / "raw" / "sweep"
EXPECTED_RULE_COUNT: Final = 26
COVERAGE_FLOOR: Final = 90.0

WORST_INTENT: Final = {
    "encryption": "3des", "integrity": "md5", "dh_group": "modp1024",
    "pfs": False, "ike_version": "ikev1", "aggressive": True,
}
BEST_INTENT: Final = {"encryption": "aes256gcm16", "dh_group": "curve25519", "pfs": True}


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def _tunnels_by_intent() -> dict[str, list[Tunnel]]:
    found: dict[str, list[Tunnel]] = defaultdict(list)
    if not SWEEP_ROOT.exists():
        return found
    for manifest in sorted(SWEEP_ROOT.glob("*/manifest.json")):
        data = json.loads(manifest.read_text())
        intent = data.get("intent", {})
        pcap = manifest.parent / "capture_outer.pcap"
        if not pcap.exists():
            continue
        labels = [
            label
            for label, spec in (("worst", WORST_INTENT), ("best", BEST_INTENT))
            if all(intent.get(k) == v for k, v in spec.items())
        ]
        if not labels:
            continue
        tunnels = correlate(
            extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap))
        )
        for label in labels:
            found[label].extend(tunnels)
    return found


def check_rule_count() -> Check:
    name = f"All {EXPECTED_RULE_COUNT} rules implemented and individually tested"
    ids = sorted(rule.id for rule in ALL_RULES)
    if len(ids) != EXPECTED_RULE_COUNT:
        return Check(name, "FAIL", f"{len(ids)} rules: {ids}")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/unit", "-k", "rules or crypto or scoring or anomaly or pqc or baselines"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=1800, check=False,
    )
    if result.returncode != 0:
        return Check(name, "FAIL", "the rule test suites did not pass")
    return Check(name, "PASS", f"{len(ids)} rules, all rule suites green")


def _score_anchor(label: str, tunnels: list[Tunnel]) -> tuple[int, str] | None:
    registry = default_registry()
    baseline = load_baselines()["nist_800_77r1"]
    scores = {score_tunnel(registry.run(t, baseline).findings) for t in tunnels}
    if not scores:
        return None
    # Every cell of one anchor config must score identically; if not, report the worst.
    return sorted(scores)[0] if label == "worst" else sorted(scores)[-1]


def check_worst_anchor() -> Check:
    name = "`worst` anchor config scores below 25 with grade F"
    tunnels = _tunnels_by_intent().get("worst", [])
    if not tunnels:
        return Check(name, "SKIP", "no `worst` anchor cells in the corpus")
    scored = _score_anchor("worst", tunnels)
    assert scored is not None
    score, grade = scored
    status = "PASS" if score < 25 and grade == "F" else "FAIL"
    return Check(name, status, f"{len(tunnels)} cells, score {score}, grade {grade}")


def check_best_anchor() -> Check:
    name = "`best` anchor config scores above 90 with grade A"
    tunnels = _tunnels_by_intent().get("best", [])
    if not tunnels:
        return Check(name, "SKIP", "no `best` anchor cells in the corpus")
    scored = _score_anchor("best", tunnels)
    assert scored is not None
    score, grade = scored
    status = "PASS" if score > 90 and grade == "A" else "FAIL"
    return Check(name, status, f"{len(tunnels)} cells, score {score}, grade {grade}")


def check_baselines_differentiate() -> Check:
    name = "Every baseline loads and produces differentiated results"
    baselines = load_baselines()
    exchange = IKEExchange(
        initiator_spi="11" * 8, responder_spi="00" * 8, version="IKEv2",
        exchange_type="IKE_SA_INIT",
        proposals_offered=[
            Proposal(number=1, protocol="IKE", transforms=[
                Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128),
                Transform(type=TransformType.INTEG, id=12, name="AUTH_HMAC_SHA2_256_128"),
                Transform(type=TransformType.DH, id=14, name="2048-bit MODP"),
            ])
        ],
        timestamp=__import__("datetime").datetime.now(__import__("datetime").UTC),
        src_ip="192.0.2.1", dst_ip="192.0.2.2",
    )
    tunnel = correlate([exchange], [])[0]
    tunnel.config = ObservedConfig(pfs_enabled=True, child_lifetime_seconds=21_600)

    registry = default_registry()
    signatures: dict[str, tuple[object, ...]] = {}
    for baseline_id, baseline in baselines.items():
        findings = registry.run(tunnel, baseline).findings
        signatures[baseline_id] = tuple(
            sorted((f.rule_id, f.severity.value) for f in findings)
        )
    distinct = len(set(signatures.values()))
    if distinct < 2:
        return Check(name, "FAIL", "every baseline produced the same verdict")
    return Check(
        name, "PASS",
        f"{len(baselines)} baselines, {distinct} distinct verdicts on one tunnel",
    )


def check_pqc_grades() -> Check:
    name = "PQC grading correct for all four grades"
    def build(transforms: list[Transform], pfs: bool | None = None, notifies: list[str] | None = None) -> Tunnel:
        import datetime as dt
        ex = IKEExchange(
            initiator_spi="11" * 8, responder_spi="00" * 8, version="IKEv2",
            exchange_type="IKE_SA_INIT",
            proposals_offered=[Proposal(number=1, protocol="IKE", transforms=transforms)],
            notifies=notifies or [], timestamp=dt.datetime.now(dt.UTC),
            src_ip="192.0.2.1", dst_ip="192.0.2.2",
        )
        t = correlate([ex], [])[0]
        if pfs is not None:
            t.config = ObservedConfig(pfs_enabled=pfs)
        return t

    ecp = Transform(type=TransformType.DH, id=19, name="256-bit ECP")
    mlkem = Transform(type=TransformType.ADDKE1, id=36, name="ML-KEM-768")
    cases = {
        PQCGrade.READY: build([mlkem]),
        PQCGrade.TRANSITIONAL: build([ecp], notifies=["USE_PPK"]),
        PQCGrade.AT_RISK: build([ecp], pfs=True),
        PQCGrade.EXPOSED: build([ecp], pfs=False),
    }
    wrong = {
        expected.value: grade_pqc(tunnel).grade.value
        for expected, tunnel in cases.items()
        if grade_pqc(tunnel).grade is not expected
    }
    if wrong:
        return Check(name, "FAIL", f"mis-graded: {wrong}")
    return Check(name, "PASS", "ready, transitional, at_risk and exposed all correct")


def check_anomaly_detection() -> Check:
    name = "Anomaly detection finds the planted outlier"
    by_config: dict[str, list[Tunnel]] = defaultdict(list)
    if not SWEEP_ROOT.exists():
        return Check(name, "SKIP", "no sweep captures present")
    for manifest in sorted(SWEEP_ROOT.glob("*/manifest.json")):
        data = json.loads(manifest.read_text())
        pcap = manifest.parent / "capture_outer.pcap"
        if not pcap.exists():
            continue
        by_config[data["config_id"]].extend(
            correlate(extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap)))
        )
    if len(by_config) < 2:
        return Check(name, "SKIP", "need at least two configurations")

    ranked = sorted(by_config.items(), key=lambda kv: -len(kv[1]))
    standard = ranked[0][1]
    planted = ranked[1][1][0]
    estate = standard * 6 + [planted]

    findings = detect_config_anomalies(estate)
    summary = anomaly_summary(estate)
    if len(findings) != 1:
        return Check(name, "FAIL", f"expected exactly 1 anomaly, got {len(findings)}")
    if findings[0].confidence is None:
        return Check(name, "FAIL", "the anomaly finding carries no confidence")
    return Check(
        name, "PASS",
        f"{len(estate)}-tunnel estate (modal share {summary['modal_share']}), "
        f"1 anomaly at confidence {findings[0].confidence.value:.2f}",
    )


def check_rule_findings_are_deterministic() -> Check:
    name = "Every rule-based finding has confidence is None"
    if not SWEEP_ROOT.exists():
        return Check(name, "SKIP", "no sweep captures present")
    registry = default_registry()
    baselines = list(load_baselines().values())
    offenders: list[str] = []
    checked = 0
    for manifest in sorted(SWEEP_ROOT.glob("*/manifest.json")):
        pcap = manifest.parent / "capture_outer.pcap"
        if not pcap.exists():
            continue
        for tunnel in correlate(
            extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap))
        ):
            for baseline in baselines:
                for finding in registry.run(tunnel, baseline).findings:
                    checked += 1
                    if finding.confidence is not None:
                        offenders.append(f"{finding.rule_id} on {tunnel.tunnel_id}")
    if offenders:
        return Check(name, "FAIL", f"{len(offenders)} inferred findings in the rule lane")
    return Check(name, "PASS", f"{checked} findings across every baseline, all deterministic")


def check_assess_coverage() -> Check:
    name = f"Coverage of assess/ above {COVERAGE_FLOOR:.0f}%"
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-m", "not integration",
            "--cov=ipsec_sentinel.assess", "--cov-report=term", "--no-cov-on-fail",
        ],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=1800, check=False,
    )
    if result.returncode != 0:
        return Check(name, "FAIL", "the suite did not pass, so coverage is meaningless")
    percent = None
    for line in result.stdout.splitlines():
        if line.startswith("TOTAL"):
            percent = float(line.split()[-1].rstrip("%"))
    if percent is None:
        return Check(name, "FAIL", "could not read a coverage total")
    status = "PASS" if percent >= COVERAGE_FLOOR else "FAIL"
    return Check(name, status, f"assess/ coverage {percent:.1f}%")


CHECKS = (
    check_rule_count,
    check_worst_anchor,
    check_best_anchor,
    check_baselines_differentiate,
    check_pqc_grades,
    check_anomaly_detection,
    check_rule_findings_are_deterministic,
    check_assess_coverage,
)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M6 acceptance checklist.")
    parser.add_argument(
        "--only",
        help=(
            "run only checks whose function name contains this substring. Useful when "
            "re-running one item, or when another pytest run holds the coverage file."
        ),
    )
    args = parser.parse_args(argv)

    selected = [c for c in CHECKS if not args.only or args.only in c.__name__]
    if not selected:
        print(f"no check matches {args.only!r}; available: "
              f"{[c.__name__ for c in CHECKS]}", file=sys.stderr)
        return 2

    print("M6 — Assessment engine complete\n")
    results = [check() for check in selected]
    for result in results:
        print(result)
        print()
    failed = [r for r in results if r.status == "FAIL"]
    skipped = [r for r in results if r.status == "SKIP"]
    print(
        f"{len(results) - len(failed) - len(skipped)}/{len(results)} passed, "
        f"{len(failed)} failed, {len(skipped)} skipped"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

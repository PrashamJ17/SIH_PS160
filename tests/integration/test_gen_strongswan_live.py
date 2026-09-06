"""Deploy a generated remediation to a live pair (build plan Step 8.2).

The plan calls this the only proof that matters, and it is right. A generated
configuration can be syntactically valid, round-trip cleanly through the parser, and
still fail to establish — because strongSwan rejects a combination the generator
believed was legal, or because the two ends were rendered inconsistently. Only bringing
a real tunnel up on the generated text settles it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ipsec_sentinel.remediate.generators.strongswan import generate_change_package, harden
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from testbed.orchestrate.netem import profile
from testbed.orchestrate.runner import CellSpec, run_cell

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


@pytest.mark.parametrize("label", ["worst", "weak"])
def test_the_corrected_configuration_establishes(label: str, tmp_path: Path) -> None:
    """A tunnel built from the hardened configuration comes up and carries ESP.

    Run through the same runner the sweep uses, so this exercises the generated
    proposal exactly as a real cell would — including the ESP guard, which fails the
    cell if the SA establishes but protects nothing.
    """
    corrected, changes = harden(anchor(label))
    assert changes, f"{label} should have something to correct"

    cell = CellSpec(corrected, generator="icmp", variant="steady_1s", impairment="clean")
    outcome = run_cell(cell, profile("clean"), duration_s=10, out_dir=tmp_path)

    assert outcome.success is True, (
        f"the corrected configuration for {label} did not establish: {outcome.error}"
    )
    assert outcome.outer_packets > 0


def test_the_generated_proposal_is_what_strongswan_negotiated(tmp_path: Path) -> None:
    """The proposal in the change package must be the one that actually comes up.

    A generator can emit a proposal strongSwan accepts while negotiating something
    else — a superset, or a fallback — and the change package would then promise a
    verification step that never passes.
    """
    import json

    original = anchor("worst")
    corrected, _ = harden(original)
    package = generate_change_package("live", original, ["CRY-05", "IKE-03"])

    cell = CellSpec(corrected, generator="icmp", variant="steady_1s", impairment="clean")
    outcome = run_cell(cell, profile("clean"), duration_s=10, out_dir=tmp_path)
    assert outcome.success is True, outcome.error

    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["negotiation_matched_intent"] is True, manifest.get("mismatches")

    negotiated = manifest["negotiated_ike"]
    assert negotiated["ike_version"] == "IKEv2", "the IKEv1 upgrade did not take effect"
    # The package's verification step promises this exact string; it must be reachable.
    assert any(corrected.proposal_string() in step for step in package.verification)


def test_a_hardened_configuration_no_longer_triggers_its_findings(tmp_path: Path) -> None:
    """Remediation is only real if the assessment stops firing on the result."""
    import json

    from ipsec_sentinel.assess.baselines.schema import get_baseline
    from ipsec_sentinel.assess.rules import default_registry
    from ipsec_sentinel.parser.correlate import correlate
    from ipsec_sentinel.parser.esp import assemble_esp_flows, extract_esp_packets
    from ipsec_sentinel.parser.pcap import extract_ike_exchanges

    corrected, _ = harden(anchor("worst"))
    cell = CellSpec(corrected, generator="icmp", variant="steady_1s", impairment="clean")
    outcome = run_cell(cell, profile("clean"), duration_s=10, out_dir=tmp_path)
    assert outcome.success is True, outcome.error

    pcap = tmp_path / "capture_outer.pcap"
    tunnels = correlate(extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap)))
    assert tunnels, "the corrected tunnel produced nothing to assess"

    registry = default_registry()
    baseline = get_baseline("nist_800_77r1")
    fired = {
        finding.rule_id for tunnel in tunnels for finding in registry.run(tunnel, baseline).findings
    }
    # The findings the hardening set out to clear.
    for rule_id in ("CRY-05", "CRY-02", "CRY-06", "IKE-01", "IKE-03"):
        assert rule_id not in fired, (
            f"{rule_id} still fires on the corrected configuration; fired: {sorted(fired)}"
        )
    assert json.loads((tmp_path / "manifest.json").read_text())["negotiation_matched_intent"]

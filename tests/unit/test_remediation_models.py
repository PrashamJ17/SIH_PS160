"""Tests for the remediation change package (build plan Step 8.1).

Both invariants here are enforced in the model rather than described in a comment,
because each is the kind of mistake that produces a confident, well-formatted document
which takes a tunnel down.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from ipsec_sentinel.remediate.models import (
    FORBIDDEN_TRANSPORTS,
    BlastRadius,
    ChangePackage,
    ChangeRisk,
    ChangeStep,
    ConfigRole,
    DeviceConfig,
)


def device(role: ConfigRole = ConfigRole.LOCAL) -> DeviceConfig:
    return DeviceConfig(
        role=role,
        vendor="strongswan",
        device_hint="gw-left",
        filename="swanctl.conf",
        content="connections { ... }",
    )


def steps() -> list[ChangeStep]:
    return [
        ChangeStep(order=1, role=ConfigRole.PEER, description="stage peer", action="edit"),
        ChangeStep(order=2, role=ConfigRole.LOCAL, description="stage local", action="edit"),
    ]


def blast() -> BlastRadius:
    return BlastRadius(risk=ChangeRisk.SINGLE_TUNNEL, tunnels_affected=1)


def package(**overrides: object) -> ChangePackage:
    payload: dict[str, object] = {
        "tunnel_id": "abc123",
        "findings_addressed": ["CRY-05"],
        "local_config": device(ConfigRole.LOCAL),
        "peer_config": device(ConfigRole.PEER),
        "sequence": steps(),
        "verification": ["swanctl --list-sas shows ESTABLISHED"],
        "rollback": ["restore the previous swanctl.conf and reload"],
        "blast_radius": blast(),
    }
    payload.update(overrides)
    return ChangePackage(**payload)  # type: ignore[arg-type]


class TestBothEndsAreMandatory:
    def test_constructing_without_peer_config_raises(self) -> None:
        """The plan's headline requirement, enforced by the model."""
        with pytest.raises(ValidationError, match="peer_config"):
            ChangePackage(
                tunnel_id="abc123",
                findings_addressed=["CRY-05"],
                local_config=device(ConfigRole.LOCAL),
                sequence=steps(),
                verification=["check"],
                rollback=["undo"],
                blast_radius=blast(),
            )  # type: ignore[call-arg]

    def test_constructing_without_local_config_raises(self) -> None:
        with pytest.raises(ValidationError, match="local_config"):
            ChangePackage(
                tunnel_id="abc123",
                findings_addressed=["CRY-05"],
                peer_config=device(ConfigRole.PEER),
                sequence=steps(),
                verification=["check"],
                rollback=["undo"],
                blast_radius=blast(),
            )  # type: ignore[call-arg]

    def test_two_configs_for_the_same_end_are_refused(self) -> None:
        """A generator bug that emits the local document twice passes a presence check.

        It leaves the far end untouched, so the tunnel drops at the next rekey rather
        than immediately — which is worse, because the change looks successful for
        hours.
        """
        with pytest.raises(ValidationError, match="one document for each end"):
            package(peer_config=device(ConfigRole.LOCAL))

    def test_a_valid_package_constructs(self) -> None:
        assert package().tunnel_id == "abc123"


class TestNonEmptyFields:
    def test_an_empty_sequence_raises(self) -> None:
        with pytest.raises(ValidationError):
            package(sequence=[])

    def test_an_empty_rollback_raises(self) -> None:
        """A change without a rollback is not a change, it is a gamble."""
        with pytest.raises(ValidationError):
            package(rollback=[])

    def test_an_empty_verification_raises(self) -> None:
        """A step nobody can check is indistinguishable from one that did nothing."""
        with pytest.raises(ValidationError):
            package(verification=[])

    def test_no_findings_addressed_raises(self) -> None:
        with pytest.raises(ValidationError):
            package(findings_addressed=[])

    def test_an_empty_config_body_raises(self) -> None:
        with pytest.raises(ValidationError):
            package(
                local_config=DeviceConfig(
                    role=ConfigRole.LOCAL,
                    vendor="strongswan",
                    device_hint="gw",
                    filename="swanctl.conf",
                    content="",
                )
            )


class TestSequenceIntegrity:
    def test_out_of_order_steps_are_refused(self) -> None:
        """The sequence is the zero-downtime guarantee and cannot be shuffled."""
        shuffled = [
            ChangeStep(order=2, role=ConfigRole.PEER, description="b", action="x"),
            ChangeStep(order=1, role=ConfigRole.LOCAL, description="a", action="y"),
        ]
        with pytest.raises(ValidationError, match="out of order"):
            package(sequence=shuffled)

    def test_duplicate_order_numbers_are_refused(self) -> None:
        duplicated = [
            ChangeStep(order=1, role=ConfigRole.LOCAL, description="a", action="x"),
            ChangeStep(order=1, role=ConfigRole.PEER, description="b", action="y"),
        ]
        with pytest.raises(ValidationError, match="share an order"):
            package(sequence=duplicated)

    def test_a_sequence_touching_only_one_end_is_refused(self) -> None:
        """Applied to one end, an IPsec change drops the tunnel at the next rekey."""
        one_sided = [
            ChangeStep(order=1, role=ConfigRole.LOCAL, description="a", action="x"),
            ChangeStep(order=2, role=ConfigRole.LOCAL, description="b", action="y"),
        ]
        with pytest.raises(ValidationError, match="only \\['local'\\]"):
            package(sequence=one_sided)

    def test_a_step_order_below_one_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            ChangeStep(order=0, role=ConfigRole.LOCAL, description="a", action="x")


class TestDerivedProperties:
    def test_reversibility_reflects_every_step(self) -> None:
        assert package().is_reversible is True
        irreversible = [
            ChangeStep(order=1, role=ConfigRole.PEER, description="a", action="x"),
            ChangeStep(
                order=2,
                role=ConfigRole.LOCAL,
                description="b",
                action="y",
                reversible=False,
            ),
        ]
        assert package(sequence=irreversible).is_reversible is False

    def test_disruption_sums_across_steps(self) -> None:
        timed = [
            ChangeStep(
                order=1, role=ConfigRole.PEER, description="a", action="x", expected_disruption_s=3
            ),
            ChangeStep(
                order=2, role=ConfigRole.LOCAL, description="b", action="y", expected_disruption_s=4
            ),
        ]
        assert package(sequence=timed).total_expected_disruption_s == 7

    def test_the_summary_names_the_risk_and_the_window(self) -> None:
        text = package(requires_maintenance_window=True).summary()
        assert "single_tunnel" in text
        assert "maintenance window required" in text

    def test_it_round_trips_through_json(self) -> None:
        original = package()
        restored = ChangePackage.model_validate_json(original.model_dump_json())
        assert restored.tunnel_id == original.tunnel_id
        assert restored.peer_config.role is ConfigRole.PEER


class TestNothingCanReachADevice:
    """The tool generates configurations; humans apply them.

    This is a hard prohibition, and it is easy to violate helpfully — adding "just an
    optional SSH push" is a one-line change that nobody reviews as a policy decision.
    """

    REMEDIATE = Path("src/ipsec_sentinel/remediate")

    def _imported_modules(self) -> set[str]:
        found: set[str] = set()
        for path in self.REMEDIATE.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    found.add(node.module.split(".")[0])
        return found

    def test_no_remote_transport_is_imported(self) -> None:
        offending = self._imported_modules() & FORBIDDEN_TRANSPORTS
        assert not offending, f"the remediation lane imports {sorted(offending)}"

    def test_subprocess_is_not_imported(self) -> None:
        """Even a local shell is a route to a device via an ssh client."""
        assert "subprocess" not in self._imported_modules()

    def test_no_socket_is_opened(self) -> None:
        assert "socket" not in self._imported_modules()

    def test_the_forbidden_list_is_not_empty(self) -> None:
        """A guard checking against an empty set passes trivially."""
        assert len(FORBIDDEN_TRANSPORTS) >= 5

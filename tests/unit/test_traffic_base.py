"""Tests for the traffic generator contract (build plan Step 2.1)."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError

from testbed.traffic.base import GenerationResult, RunContext, TrafficGenerator

START = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
END = START + timedelta(seconds=60)


def result(**kw: object) -> GenerationResult:
    base: dict[str, object] = {
        "generator": "icmp",
        "variant": "steady_1s",
        "packets_sent": 60,
        "bytes_sent": 3840,
        "started_at": START,
        "ended_at": END,
        "success": True,
    }
    base.update(kw)
    return GenerationResult(**base)  # type: ignore[arg-type]


def context() -> RunContext:
    return RunContext(
        project="sentinel-test",
        left_gateway="left-gw",
        right_gateway="right-gw",
        left_host="left-host",
        right_host="right-host",
        left_host_ip="10.1.0.10",
        right_host_ip="10.2.0.10",
        out_dir=Path("/tmp/out"),
    )


class Dummy:
    """A minimal conforming generator that records what it was given."""

    name = "dummy"
    requires: ClassVar[list[str]] = []

    def __init__(self) -> None:
        self.ctx: RunContext | None = None
        self.ran_for: int | None = None
        self.torn_down = False

    def setup(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def run(self, duration_s: int) -> GenerationResult:
        self.ran_for = duration_s
        return result(generator=self.name, variant="v1")

    def teardown(self) -> None:
        self.torn_down = True


class MissingRun:
    """Conforms except for run(): must be rejected."""

    name = "broken"
    requires: ClassVar[list[str]] = []

    def setup(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def teardown(self) -> None:
        return None


class MissingName:
    """Conforms except for the class label: must be rejected."""

    requires: ClassVar[list[str]] = []

    def setup(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def run(self, duration_s: int) -> GenerationResult:
        return result(packets_sent=duration_s)

    def teardown(self) -> None:
        return None


class TestProtocolConformance:
    def test_a_conforming_generator_satisfies_the_protocol(self) -> None:
        assert isinstance(Dummy(), TrafficGenerator)

    def test_a_generator_missing_a_method_does_not_satisfy_it(self) -> None:
        assert not isinstance(MissingRun(), TrafficGenerator)

    def test_a_generator_missing_the_class_label_does_not_satisfy_it(self) -> None:
        """name becomes the ML class label, so its absence is not a detail."""
        assert not isinstance(MissingName(), TrafficGenerator)

    def test_the_protocol_round_trips_through_the_full_lifecycle(self) -> None:
        gen = Dummy()
        ctx = context()
        gen.setup(ctx)
        outcome = gen.run(10)
        gen.teardown()
        assert gen.ctx is ctx
        assert gen.ran_for == 10
        assert gen.torn_down is True
        assert outcome.generator == "dummy"
        assert outcome.success is True


class TestGenerationResultInvariants:
    def test_failure_must_carry_an_error(self) -> None:
        with pytest.raises(ValidationError, match="explaining why"):
            result(success=False)

    def test_failure_with_an_error_is_valid(self) -> None:
        assert result(success=False, error="ping exited 1").error == "ping exited 1"

    def test_failure_with_an_empty_error_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="explaining why"):
            result(success=False, error="")

    def test_success_must_not_carry_an_error(self) -> None:
        """A run reported as both successful and failed is a bug, not a state."""
        with pytest.raises(ValidationError, match="must not carry an error"):
            result(success=True, error="something went wrong")

    def test_success_without_an_error_is_valid(self) -> None:
        assert result().success is True

    def test_end_before_start_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="precedes"):
            result(started_at=END, ended_at=START)

    def test_equal_timestamps_are_allowed(self) -> None:
        assert result(started_at=START, ended_at=START).duration_s == 0.0

    def test_duration_is_derived_from_the_timestamps(self) -> None:
        assert result().duration_s == 60.0

    @pytest.mark.parametrize("field", ["packets_sent", "bytes_sent"])
    def test_counters_cannot_be_negative(self, field: str) -> None:
        with pytest.raises(ValidationError):
            result(**{field: -1})

    def test_zero_counters_are_allowed(self) -> None:
        """An idle generator legitimately sends nothing."""
        assert result(packets_sent=0, bytes_sent=0).packets_sent == 0

    def test_round_trips_through_json(self) -> None:
        original = result()
        assert GenerationResult.model_validate_json(original.model_dump_json()) == original


class TestRunContext:
    def test_is_frozen(self) -> None:
        ctx = context()
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.project = "other"  # type: ignore[misc]

    def test_carries_the_host_endpoints_generators_drive(self) -> None:
        """Generators drive the hosts; gateway-originated traffic misses the inner tap."""
        ctx = context()
        assert ctx.left_host_ip == "10.1.0.10"
        assert ctx.right_host_ip == "10.2.0.10"

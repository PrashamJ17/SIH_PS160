"""Generators must address sidecars from the run context, not from constants.

This guards a bug that was genuinely expensive to find. The sweep runs concurrent
pairs in disjoint subnets, so every address a generator uses has to come from its
RunContext. A generator that reaches for the module-level default instead still
*passes its readiness check* — because that check was correctly updated — and then
talks to an address that does not exist in its slot, producing a cell that fails with
a bare timeout and no indication of why.

The module constants remain as slot-0 defaults for RunContext; what must never happen
is a generator using one at call time.
"""

from __future__ import annotations

import inspect
import re

import pytest

from testbed.traffic import email, messaging, video, web
from testbed.traffic.base import RunContext

SIDECAR_CONSTANTS = {
    video: ("VIDEO_ORIGIN_IP", "video_origin_ip"),
    web: ("WEB_ORIGIN_IP", "web_origin_ip"),
    email: ("MAIL_ORIGIN_IP", "mail_origin_ip"),
    messaging: ("XMPP_ORIGIN_IP", "xmpp_origin_ip"),
}

GENERATORS = {
    video: video.VideoGenerator,
    web: web.WebGenerator,
    email: email.EmailGenerator,
    messaging: messaging.MessagingGenerator,
}


@pytest.mark.parametrize("module", list(SIDECAR_CONSTANTS), ids=lambda m: m.__name__)
def test_no_generator_uses_a_hardcoded_sidecar_address(module: object) -> None:
    """The whole class body must route sidecar addresses through the context."""
    constant, _attribute = SIDECAR_CONSTANTS[module]
    source = inspect.getsource(GENERATORS[module])
    offenders = re.findall(rf"\b{constant}\b", source)
    assert not offenders, (
        f"{module.__name__}.{GENERATORS[module].__name__} references {constant} "
        f"directly; in a sweep slot that address does not exist"
    )


@pytest.mark.parametrize("module", list(SIDECAR_CONSTANTS), ids=lambda m: m.__name__)
def test_the_context_attribute_is_actually_used(module: object) -> None:
    _constant, attribute = SIDECAR_CONSTANTS[module]
    source = inspect.getsource(GENERATORS[module])
    assert f"ctx.{attribute}" in source or f"self._ctx.{attribute}" in source, (
        f"{module.__name__} never reads ctx.{attribute}"
    )


@pytest.mark.parametrize("module", list(SIDECAR_CONSTANTS), ids=lambda m: m.__name__)
def test_the_module_constant_still_matches_the_context_default(module: object) -> None:
    """The constants remain as slot-0 documentation; they must not drift."""
    constant, attribute = SIDECAR_CONSTANTS[module]
    default = RunContext.__dataclass_fields__[attribute].default
    assert getattr(module, constant) == default


def test_run_context_exposes_every_sidecar_address() -> None:
    fields = set(RunContext.__dataclass_fields__)
    for _constant, attribute in SIDECAR_CONSTANTS.values():
        assert attribute in fields


def test_run_context_exposes_the_gateway_protected_address() -> None:
    """The replay generator needs the gateway's own MAC, addressed on the protected side."""
    assert "left_protected_ip" in RunContext.__dataclass_fields__


def test_replay_does_not_hardcode_the_gateway_address() -> None:
    from testbed.traffic.replay import ReplayGenerator

    source = inspect.getsource(ReplayGenerator)
    assert '"10.1.0.2"' not in source
    assert "ctx.left_protected_ip" in source

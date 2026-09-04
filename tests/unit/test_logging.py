"""Tests for structured logging (build plan Step 0.5)."""

from __future__ import annotations

import json
import logging

import pytest

from ipsec_sentinel.logging import (
    ENV_FORMAT,
    ENV_LEVEL,
    HANDLER_NAME,
    ROOT_LOGGER_NAME,
    get_logger,
    reset,
)


@pytest.fixture(autouse=True)
def _clean_logging() -> None:
    """Every test starts from an unconfigured logger."""
    reset()


class TestSameInstance:
    def test_same_name_returns_same_instance(self) -> None:
        assert get_logger("alpha") is get_logger("alpha")

    def test_different_names_return_different_instances(self) -> None:
        assert get_logger("alpha") is not get_logger("beta")

    def test_name_is_namespaced_under_the_package(self) -> None:
        assert get_logger("sweep").name == f"{ROOT_LOGGER_NAME}.sweep"

    def test_dunder_name_is_not_double_prefixed(self) -> None:
        """get_logger(__name__) from inside the package must not stutter."""
        inner = f"{ROOT_LOGGER_NAME}.parser.ike"
        assert get_logger(inner).name == inner

    def test_repeated_calls_do_not_duplicate_handlers(self) -> None:
        """A duplicated handler would emit every record twice.

        Count only our own handler: pytest attaches LogCaptureHandlers of its own.
        """
        for _ in range(5):
            get_logger("alpha")
        root = logging.getLogger(ROOT_LOGGER_NAME)
        ours = [h for h in root.handlers if h.get_name() == HANDLER_NAME]
        assert len(ours) == 1


class TestJSONMode:
    def test_json_mode_emits_parseable_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "json")
        get_logger("alpha").warning("tunnel down")
        line = capsys.readouterr().err.strip()
        payload = json.loads(line)
        assert payload["level"] == "WARNING"
        assert payload["name"] == f"{ROOT_LOGGER_NAME}.alpha"
        assert payload["message"] == "tunnel down"

    def test_json_mode_is_case_insensitive(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "JSON")
        get_logger("alpha").warning("hello")
        json.loads(capsys.readouterr().err.strip())

    def test_json_message_interpolates_args(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "json")
        get_logger("alpha").warning("spi %s down", "0xdeadbeef")
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["message"] == "spi 0xdeadbeef down"

    def test_json_carries_extra_fields(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Structured context is what makes the logs greppable."""
        monkeypatch.setenv(ENV_FORMAT, "json")
        get_logger("alpha").warning("weak proposal", extra={"spi": "0xabc", "dh_group": 2})
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["spi"] == "0xabc"
        assert payload["dh_group"] == 2

    def test_json_records_exception_text(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "json")
        try:
            raise ValueError("truncated payload")
        except ValueError:
            get_logger("alpha").exception("parse failed")
        payload = json.loads(capsys.readouterr().err.strip())
        assert "ValueError: truncated payload" in payload["exception"]

    def test_json_records_stack_info_when_requested(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "json")
        get_logger("alpha").warning("weak proposal", stack_info=True)
        payload = json.loads(capsys.readouterr().err.strip())
        assert "Stack (most recent call last)" in payload["stack"]

    def test_json_output_is_one_object_per_line(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "json")
        log = get_logger("alpha")
        log.warning("first")
        log.warning("second")
        lines = capsys.readouterr().err.strip().splitlines()
        assert len(lines) == 2
        assert [json.loads(x)["message"] for x in lines] == ["first", "second"]


class TestHumanMode:
    def test_default_mode_is_human_readable_not_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv(ENV_FORMAT, raising=False)
        get_logger("alpha").warning("tunnel down")
        err = capsys.readouterr().err.strip()
        assert "tunnel down" in err
        assert "WARNING" in err
        with pytest.raises(json.JSONDecodeError):
            json.loads(err)

    def test_unknown_format_falls_back_to_human(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_FORMAT, "yaml-ish-nonsense")
        get_logger("alpha").warning("tunnel down")
        with pytest.raises(json.JSONDecodeError):
            json.loads(capsys.readouterr().err.strip())


class TestLevel:
    def test_level_respects_the_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_LEVEL, "DEBUG")
        assert get_logger("alpha").getEffectiveLevel() == logging.DEBUG

    def test_default_level_is_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_LEVEL, raising=False)
        assert get_logger("alpha").getEffectiveLevel() == logging.INFO

    def test_level_is_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_LEVEL, "warning")
        assert get_logger("alpha").getEffectiveLevel() == logging.WARNING

    def test_numeric_level_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_LEVEL, "30")
        assert get_logger("alpha").getEffectiveLevel() == logging.WARNING

    def test_invalid_level_falls_back_to_info_without_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Logging setup must never be the thing that crashes the tool."""
        monkeypatch.setenv(ENV_LEVEL, "LOUDER")
        assert get_logger("alpha").getEffectiveLevel() == logging.INFO

    def test_level_filters_records_below_threshold(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_LEVEL, "WARNING")
        log = get_logger("alpha")
        log.info("suppressed")
        log.warning("shown")
        err = capsys.readouterr().err
        assert "suppressed" not in err
        assert "shown" in err

    def test_env_change_between_calls_is_picked_up(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_LEVEL, "ERROR")
        assert get_logger("alpha").getEffectiveLevel() == logging.ERROR
        monkeypatch.setenv(ENV_LEVEL, "DEBUG")
        assert get_logger("alpha").getEffectiveLevel() == logging.DEBUG


class TestIsolation:
    def test_records_do_not_propagate_to_the_root_logger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Otherwise a host application's root handler double-prints our logs."""
        monkeypatch.delenv(ENV_FORMAT, raising=False)
        get_logger("alpha")
        assert logging.getLogger(ROOT_LOGGER_NAME).propagate is False

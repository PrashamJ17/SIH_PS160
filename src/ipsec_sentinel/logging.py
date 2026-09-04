"""Structured logging for IPsec Sentinel.

Every module logs through :func:`get_logger`. Two output modes are selected by the
``SENTINEL_LOG_FORMAT`` environment variable:

``json``
    One JSON object per line, carrying ``timestamp``, ``level``, ``name`` and
    ``message`` plus any structured context passed via ``extra=``. This is the mode
    to use when shipping to a SIEM or grepping a sweep of several thousand runs.

anything else (the default)
    A human-readable line, for a terminal.

The threshold comes from ``SENTINEL_LOG_LEVEL`` (default ``INFO``); it accepts a level
name in any case, or a numeric level. An unrecognised value falls back to ``INFO``
rather than raising — logging setup must never be the thing that crashes the tool.

Records go to **stderr**, leaving stdout clean for machine-readable output such as a
piped JSON report.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Final

ROOT_LOGGER_NAME: Final = "ipsec_sentinel"
ENV_LEVEL: Final = "SENTINEL_LOG_LEVEL"
ENV_FORMAT: Final = "SENTINEL_LOG_FORMAT"
DEFAULT_LEVEL: Final = logging.INFO
JSON_FORMAT_NAME: Final = "json"

HANDLER_NAME: Final = "ipsec-sentinel-handler"
_HUMAN_FORMAT: Final = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

# Attributes the stdlib puts on every LogRecord. Anything outside this set was supplied
# by the caller through ``extra=`` and is therefore structured context worth emitting.
_STANDARD_RECORD_FIELDS: Final = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "stacklevel",
        "taskName",
        "thread",
        "threadName",
    }
)

# The (level, format-mode) pair currently installed on the package logger.
_installed_config: tuple[int, str] | None = None


class JSONFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_FIELDS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=repr)


def _resolve_level() -> int:
    """Read the level from the environment, defaulting rather than raising."""
    raw = os.environ.get(ENV_LEVEL, "").strip()
    if not raw:
        return DEFAULT_LEVEL
    if raw.isdigit():
        return int(raw)
    named = logging.getLevelName(raw.upper())
    # getLevelName returns the string "Level FOO" for anything it does not know.
    return named if isinstance(named, int) else DEFAULT_LEVEL


def _resolve_format() -> str:
    """Return the format mode: ``json`` or ``human``."""
    raw = os.environ.get(ENV_FORMAT, "").strip().lower()
    return JSON_FORMAT_NAME if raw == JSON_FORMAT_NAME else "human"


def _build_handler(mode: str) -> logging.Handler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JSONFormatter() if mode == JSON_FORMAT_NAME else logging.Formatter(_HUMAN_FORMAT)
    )
    handler.set_name(HANDLER_NAME)
    return handler


def _qualify(name: str) -> str:
    """Namespace a logger under the package root, without stuttering.

    ``get_logger(__name__)`` from inside the package is already qualified; a bare
    label like ``"sweep"`` is not.
    """
    if name == ROOT_LOGGER_NAME or name.startswith(f"{ROOT_LOGGER_NAME}."):
        return name
    return f"{ROOT_LOGGER_NAME}.{name}"


def reset() -> None:
    """Detach our handler and forget the installed configuration.

    Used by tests to guarantee a clean slate, and by the CLI when an explicit
    ``--log-format`` or ``--log-level`` flag must override the environment.
    """
    global _installed_config
    root = logging.getLogger(ROOT_LOGGER_NAME)
    for handler in [h for h in root.handlers if h.get_name() == HANDLER_NAME]:
        root.removeHandler(handler)
        handler.close()
    _installed_config = None


def get_logger(name: str) -> logging.Logger:
    """Return the logger for ``name``, configuring the package logger on first use.

    The same ``name`` always yields the same underlying logger instance. The handler
    is installed exactly once and rebuilt only when the environment asks for a
    different level or format, so repeated calls never duplicate output.
    """
    global _installed_config
    desired = (_resolve_level(), _resolve_format())
    if desired != _installed_config:
        root = logging.getLogger(ROOT_LOGGER_NAME)
        for handler in [h for h in root.handlers if h.get_name() == HANDLER_NAME]:
            root.removeHandler(handler)
            handler.close()
        root.addHandler(_build_handler(desired[1]))
        root.setLevel(desired[0])
        # Do not hand records to a host application's root handler as well.
        root.propagate = False
        _installed_config = desired
    return logging.getLogger(_qualify(name))

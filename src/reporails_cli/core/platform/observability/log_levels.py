"""Logging setup for the package's entry points, and temporary logger level changes."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from reporails_cli.core.platform.config.bootstrap import env_flag
from reporails_cli.core.platform.observability import stage_timer

_PACKAGE_LOGGER = "reporails_cli"


class _StderrHandler(logging.Handler):
    """Writes each record as its message, plus any traceback, to whatever `sys.stderr` is at emit time."""

    def emit(self, record: logging.LogRecord) -> None:
        """Write the formatted record and a newline to the current stderr."""
        try:
            sys.stderr.write(f"{self.format(record)}\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            self.handleError(record)


def configure_logging() -> None:
    """Send the package's log records to stderr as bare messages, once per process.

    When the root logger already has a handler, records reach it and no second one is added.
    When `AILS_STAGE_TIMING` is on, stage timing records print at INFO.
    """
    package_logger = logging.getLogger(_PACKAGE_LOGGER)
    if not logging.getLogger().handlers and not any(isinstance(h, _StderrHandler) for h in package_logger.handlers):
        package_logger.addHandler(_StderrHandler())
    if env_flag("AILS_STAGE_TIMING"):
        logging.getLogger(stage_timer.__name__).setLevel(logging.INFO)


@contextmanager
def quiet_loggers(names: Iterable[str]) -> Iterator[None]:
    """Hold the named loggers at ERROR for the block and restore their previous levels on exit."""
    previous = {name: logging.getLogger(name).level for name in names}
    for name in previous:
        logging.getLogger(name).setLevel(logging.ERROR)
    try:
        yield
    finally:
        for name, old in previous.items():
            logging.getLogger(name).setLevel(old)

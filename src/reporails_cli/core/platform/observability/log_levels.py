"""Logging setup for the package's entry points, and temporary logger level changes."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from reporails_cli.core.platform.observability import stage_timer

_PACKAGE_LOGGER = "reporails_cli"


class _StderrHandler(logging.Handler):
    """Writes bare messages to whatever `sys.stderr` is at emit time."""

    def emit(self, record: logging.LogRecord) -> None:
        """Write the record's message and a newline to the current stderr."""
        try:
            sys.stderr.write(f"{record.getMessage()}\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            self.handleError(record)


def configure_logging() -> None:
    """Send the package's log records to stderr as bare messages, once per process.

    Resets the stage timer; when stage timing is on, its records print at INFO.
    """
    package_logger = logging.getLogger(_PACKAGE_LOGGER)
    if not any(isinstance(h, _StderrHandler) for h in package_logger.handlers):
        package_logger.addHandler(_StderrHandler())
    timer = stage_timer.get_stage_timer()
    timer.reset()
    if timer.enabled:
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

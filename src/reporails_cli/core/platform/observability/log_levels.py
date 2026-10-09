"""Temporarily raise logger levels, then give them back."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from contextlib import contextmanager


@contextmanager
def quiet_loggers(names: Iterable[str], level: int = logging.ERROR) -> Iterator[None]:
    """Hold the named loggers at `level` for the block and restore their previous levels on exit."""
    previous = {name: logging.getLogger(name).level for name in names}
    for name in previous:
        logging.getLogger(name).setLevel(level)
    try:
        yield
    finally:
        for name, old in previous.items():
            logging.getLogger(name).setLevel(old)

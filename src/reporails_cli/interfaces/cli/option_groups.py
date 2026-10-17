"""Typer commands whose options are the fields of one dataclass.

A command with many options would otherwise need one function parameter per option. Declaring
the options as dataclass fields (each default a `typer.Option` / `typer.Argument`) keeps the
callback to a single argument while Typer still builds the same flags and help.
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, get_type_hints

if TYPE_CHECKING:
    from _typeshed import DataclassInstance


class OptionsCommand(Protocol):  # pylint: disable=too-few-public-methods  # a callable protocol is one method
    """A Typer command taking one keyword argument per option."""

    def __call__(self, **values: object) -> None:
        """Run the command with each option's parsed value."""


def command_options[Options: DataclassInstance](
    options_type: type[Options],
) -> Callable[[Callable[[Options], None]], OptionsCommand]:
    """Decorate a callback taking `options_type` so Typer sees one parameter per dataclass field."""
    hints = get_type_hints(options_type)
    parameters = [
        inspect.Parameter(
            field.name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=field.default,
            annotation=hints[field.name],
        )
        for field in dataclasses.fields(options_type)
    ]

    def decorate(callback: Callable[[Options], None]) -> OptionsCommand:
        @functools.wraps(callback)
        def command(**values: object) -> None:
            callback(options_type(**values))

        command.__dict__["__signature__"] = inspect.Signature(parameters, return_annotation=None)
        command.__annotations__ = {**hints, "return": type(None)}
        return command

    return decorate

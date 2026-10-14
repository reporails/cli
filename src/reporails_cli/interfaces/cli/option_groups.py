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
from typing import Any, cast, get_type_hints


def command_options[Options](options_type: type[Options]) -> Callable[[Callable[[Options], None]], Callable[..., None]]:
    """Decorate a callback taking `options_type` so Typer sees one parameter per dataclass field."""
    hints = get_type_hints(options_type)
    parameters = [
        inspect.Parameter(
            field.name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=field.default,
            annotation=hints[field.name],
        )
        for field in dataclasses.fields(cast(Any, options_type))
    ]

    def decorate(callback: Callable[[Options], None]) -> Callable[..., None]:
        @functools.wraps(callback)
        def command(**values: Any) -> None:
            callback(options_type(**values))

        cast(Any, command).__signature__ = inspect.Signature(parameters, return_annotation=None)
        command.__annotations__ = {**hints, "return": type(None)}
        return command

    return decorate

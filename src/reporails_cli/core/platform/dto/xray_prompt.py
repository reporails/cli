"""The shape of a recorded system prompt: its top-level sections and their sizes, never their text."""

from __future__ import annotations

from dataclasses import dataclass

from reporails_cli.core.platform.contract.json_value import JsonObject

# The heading of the text that comes before a prompt's first heading.
OPENING_HEADING = "Opening"


@dataclass(frozen=True)
class PromptSection:
    """One top-level section of a system prompt: its heading and the characters from its heading line to the next."""

    heading: str
    chars: int

    def to_json(self) -> JsonObject:
        """The section as a JSON object."""
        return {"heading": self.heading, "chars": self.chars}

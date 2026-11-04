"""The excluded-folder record."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Literal, get_args

from reporails_cli.core.platform.contract.glob_pattern import escape_glob, glob_matches
from reporails_cli.core.platform.contract.json_value import JsonObject


@dataclass(frozen=True)
class FolderValue:
    """One excluded folder: a name matched at any depth, or a path anchored at the project root."""

    parts: tuple[str, ...]
    anchored: bool = False

    def __post_init__(self) -> None:
        if not self.parts or not all(self.parts):
            raise ValueError("a folder value holds at least one part, and no part is empty")
        if not self.anchored and len(self.parts) > 1:
            raise ValueError("a folder name holds one part; a folder path is anchored")

    @cached_property
    def glob(self) -> str:
        """The folder as a glob that matches only that folder: any depth for a name, from the root for a path."""
        if not self.anchored:
            return "**/" + escape_glob(self.parts[0])
        return "/".join(escape_glob(part) for part in self.parts)

    def holds(self, rel: str) -> bool:
        """True when the root-relative posix path `rel` is this folder or lies under it."""
        if not rel:
            return False
        return glob_matches(rel, self.glob, anchored=True, prefix=True)

    @property
    def text(self) -> str:
        """The folder as reported: `docs`, `pkg/docs`, or `./docs` for a single anchored folder."""
        if not self.anchored:
            return self.parts[0]
        joined = "/".join(self.parts)
        return joined if len(self.parts) > 1 else "./" + joined


# The settings that keep a file out of a check or a fix.
ExclusionSetting = Literal["exclude_dirs", "exclude_files", "heal_exclude"]
EXCLUSION_SETTINGS: tuple[ExclusionSetting, ...] = get_args(ExclusionSetting)


@dataclass(frozen=True)
class ExclusionHit:
    """One setting value that keeps a file out: the setting, the value as written and the config file holding it."""

    setting: ExclusionSetting
    value: str
    config: str

    def to_json(self) -> JsonObject:
        """The hit as a JSON object."""
        return {"setting": self.setting, "value": self.value, "config": self.config}


@dataclass(frozen=True)
class FileLeftOut:
    """What keeps a file out of a project-wide check or fix and out of the page's buttons: the config values that
    leave it out, and where its link leads when the file is a link to a place outside the project."""

    hits: tuple[ExclusionHit, ...] = ()
    outside: str | None = None

    def to_json(self) -> JsonObject:
        """The facts as a JSON object."""
        return {"hits": [hit.to_json() for hit in self.hits], "outside": self.outside}

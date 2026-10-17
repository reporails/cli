"""The output formats the `check` and `rules` commands accept, with their named groups."""

from __future__ import annotations

from typing import Literal, get_args

CheckFormat = Literal["text", "json", "github"]
RulesListFormat = Literal["text", "md", "json"]

# Accepted values of `ails check --format`, in the order help text names them.
CHECK_FORMATS: tuple[CheckFormat, ...] = get_args(CheckFormat)
# Check formats a program reads: they carry no progress display and no human notices.
MACHINE_READABLE_CHECK_FORMATS: tuple[CheckFormat, ...] = tuple(f for f in CHECK_FORMATS if f != "text")

# Accepted values of `ails rules list --format`.
RULES_LIST_FORMATS: tuple[RulesListFormat, ...] = get_args(RulesListFormat)
# Rules-list formats that need no Markdown rendering: `rules agents` and `rules explain` accept these.
RULES_PLAIN_FORMATS: tuple[RulesListFormat, ...] = tuple(f for f in RULES_LIST_FORMATS if f != "md")

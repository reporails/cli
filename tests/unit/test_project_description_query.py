"""CORE:C:0013 — a project description is a matching heading OR the lead block under the title.

Drives the REAL tokenizer, so the atom kinds, charges, and word counts the query reads are
the ones the mapper actually produces.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.content_queries import has_project_description
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.platform.dto.ruleset import RulesetMap

_TERMS = ["Description", "About", "Overview"]


def _found(md: str) -> bool:
    atoms = tokenize(md)
    for a in atoms:
        a.file_path = "CLAUDE.md"
    rm = RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=tuple(atoms),
    )
    return has_project_description(rm, "CLAUDE.md", terms=_TERMS).found


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "md",
    [
        "# Acme API\n\nA REST API that manages user accounts and billing for Acme tenants.\n\n## Commands\n",
        "# Acme API\n\n> A REST API that manages user accounts and billing for Acme tenants.\n\n## Commands\n",
        "# Acme API\n\n## Overview\n\nUser management.\n",
    ],
    ids=["title-then-sentence", "title-then-blockquote", "matching-heading"],
)
def test_description_present(md: str) -> None:
    assert _found(md)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "md",
    [
        "# Acme API\n\n## Commands\n\n- Run `npm test` before every commit to the `main` branch.\n",
        "# Acme API\n\n- Run `npm test` before every commit to the `main` branch.\n",
        "# Acme API\n\nSee docs.\n\n## Commands\n",
        "# Acme API\n\n## Background\n\nA REST API that manages user accounts and billing for Acme tenants.\n",
        # The tokenizer marks this AMBIGUOUS with charge 0: instruction-shaped, not a description.
        "# Acme API\n\nIt is important that migrations are always reversible in this codebase.\n\n## Commands\n",
        "# Acme API\n\n- Run `npm test` before every commit to the `main` branch.\n\n"
        "This file is maintained by the platform team at Acme.\n",
    ],
    ids=[
        "title-then-section",
        "title-then-instructions",
        "too-short-to-describe",
        "under-non-matching-section",
        "instruction-shaped-lead",
        "prose-after-instructions",
    ],
)
def test_description_absent(md: str) -> None:
    assert not _found(md)

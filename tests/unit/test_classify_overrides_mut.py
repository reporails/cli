"""Mutation-killing behavioral tests for core/classify/__init__.py survivors.

Covers the project-override merge (`surfaces`/`agents` getattr-or guards and the
`decl.name == "main"` fallback gate), the `generic_scanning` default, and the
freeform-format `and` predicate. The `current == root or current ==
current.parent` operators in `_compute_ancestor_chain` (L202) are equivalent
mutants: for the scan roots these tests use, the ancestor chain resolves to the
single `{scan_root}` regardless of which equality flips, so no observable output
changes — left undecorated.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reporails_cli.core.classify import _apply_project_overrides, classify_files
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.models import FileTypeDeclaration
from reporails_cli.core.platform.dto.results import ProjectConfig


def _project_config(root: Path, **sections: object) -> ProjectConfig:
    """The config a real `.ails/config.yml` under `root` holds, as one run reads it."""
    (root / ".ails").mkdir(exist_ok=True)
    (root / ".ails" / "config.yml").write_text(yaml.safe_dump(sections), encoding="utf-8")
    return RunContext().project_config(root)


# --- _apply_project_overrides: surfaces getattr-or (L91) ------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_surface_include_patterns_are_merged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _project_config(tmp_path, surfaces={"claude.main": {"include": ["EXTRA.md"]}})
    decls = [FileTypeDeclaration(name="main", patterns=("CLAUDE.md",))]
    out = _apply_project_overrides(decls, "claude", config)
    # `or`->`and` collapses a truthy surfaces dict to {} and drops the include.
    assert "EXTRA.md" in out[0].patterns


# --- agents getattr-or (L92) + decl.name == "main" gate (L102) ------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_main_fallback_filenames_are_merged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _project_config(tmp_path, agents={"claude": {"fallback_filenames": ["FALLBACK.md"]}})
    decls = [FileTypeDeclaration(name="main", patterns=("CLAUDE.md",))]
    out = _apply_project_overrides(decls, "claude", config)
    # `or`->`and` drops the agents dict; `==`->`!=` skips the main declaration.
    assert "**/FALLBACK.md" in out[0].patterns


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_non_main_declaration_gets_no_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _project_config(tmp_path, agents={"claude": {"fallback_filenames": ["FALLBACK.md"]}})
    decls = [FileTypeDeclaration(name="skills", patterns=("SKILL.md",))]
    out = _apply_project_overrides(decls, "claude", config)
    # `==`->`!=` would apply the main fallback to this non-main declaration.
    assert "**/FALLBACK.md" not in out[0].patterns
    assert out[0].patterns == ("SKILL.md",)


# --- classify_files: generic_scanning default (L270) ----------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_generic_scanning_off_by_default(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    claude.write_text("# Project\n\nSee [notes](notes.md).\n")
    notes = tmp_path / "notes.md"
    notes.write_text("# Notes\n\nProse.\n")
    ft = FileTypeDeclaration(
        name="main", patterns=("CLAUDE.md",), properties={"format": "freeform", "scope": "project"}
    )
    # No generic_scanning arg -> default False -> the linked notes.md is NOT
    # pulled in as a generic file. `False -> True` would add it.
    result = classify_files(tmp_path, [claude, notes], [ft])
    assert len(result) == 1
    assert all(cf.file_type != "generic" for cf in result)


# --- classify_files: freeform format predicate (L325) ---------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_substring_freeform_format_is_not_freeform(tmp_path: Path) -> None:
    md = tmp_path / "CLAUDE.md"
    md.write_text("# Heading\n\nSome real paragraph content here.\n")
    # A str format that merely CONTAINS "freeform" is not freeform. The `and`
    # guards the list branch; `and`->`or` makes `"freeform" in "xfreeform"`
    # fire and wrongly detect content_format.
    ft = FileTypeDeclaration(name="main", patterns=("CLAUDE.md",), properties={"format": "xfreeform"})
    result = classify_files(tmp_path, [md], [ft])
    assert len(result) == 1
    assert "content_format" not in result[0].properties

"""Unit tests for the public-rule fix gate — the re-leak floor.

Fix / remediation text is paid content that no longer lives in the open
``framework/rules/`` tree. The gate fails the build if any ``rule.md`` carries a
``fix:`` frontmatter field or a ``## Fix`` body section — the mechanical floor
behind the schema's retired-``fix:`` note.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GATE_PATH = _REPO_ROOT / "scripts" / "no_public_fix_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("no_public_fix_gate", _GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_gate = _load_gate()


def _rule(root: Path, slug: str, body: str) -> Path:
    d = root / slug
    d.mkdir(parents=True)
    path = d / "rule.md"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_clean_rule_passes(tmp_path: Path) -> None:
    """A rule carrying only diagnosis content is not flagged."""
    _rule(tmp_path, "size-limits", "---\nid: CORE:S:0001\nslug: size-limits\n---\n\n## Antipatterns\n")
    assert _gate.find_public_fix(tmp_path) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_frontmatter_field_fires(tmp_path: Path) -> None:
    """A `fix:` frontmatter field re-leaks paid content and is caught."""
    offender = _rule(
        tmp_path,
        "leaky",
        "---\nid: CORE:S:0002\nslug: leaky\nfix: >\n  Rewrite the directive to name the file.\n---\n",
    )
    assert _gate.find_public_fix(tmp_path) == [offender]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_body_section_fires(tmp_path: Path) -> None:
    """A `## Fix` body section is caught the same as the frontmatter field."""
    offender = _rule(
        tmp_path,
        "leaky-body",
        "---\nid: CORE:S:0003\nslug: leaky-body\n---\n\n## Fix\n\nDo the thing.\n",
    )
    assert _gate.find_public_fix(tmp_path) == [offender]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_live_framework_rules_are_clean() -> None:
    """The shipped rule tree carries no fix content — the state the gate protects."""
    assert _gate.find_public_fix(_gate.RULES_ROOT) == []


_INVENTED_CATALOG = (
    "levers:\n  sample:\n    action: Relocate every purple heron statue beside the lighthouse keeper before sunrise.\n"
)


def _catalog(tmp_path: Path) -> Path:
    path = tmp_path / "catalog.yml"
    path.write_text(_INVENTED_CATALOG, encoding="utf-8")
    return path


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_public_doc_repeating_catalog_run_fails(tmp_path: Path) -> None:
    """A changelog line sharing an eight-word run with a catalog sentence is named with its line."""
    doc = tmp_path / "UNRELEASED.md"
    doc.write_text(
        "- Check: a note.\n- Check: it says to relocate every purple heron statue beside the lighthouse keeper.\n",
        encoding="utf-8",
    )
    assert _gate.find_doc_overlap([doc], _catalog(tmp_path)) == [(doc, [2])]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_public_doc_reworded_passes(tmp_path: Path) -> None:
    """The same entry reworded to state the outcome shares no eight-word run."""
    doc = tmp_path / "UNRELEASED.md"
    doc.write_text("- Check: statues near the keeper are reported; a paid plan offers a fix.\n", encoding="utf-8")
    assert _gate.find_doc_overlap([doc], _catalog(tmp_path)) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_gate_main_names_offending_doc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The gate exits 1 and names the public file and line; reworded, it exits 0."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "framework" / "rules").mkdir(parents=True)
    readme = tmp_path / "README.md"
    readme.write_text(
        "Relocate every purple heron statue beside the lighthouse keeper before sunrise.\n", encoding="utf-8"
    )
    monkeypatch.setattr(_gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(_gate, "RULES_ROOT", tmp_path / "framework" / "rules")
    monkeypatch.setenv("AILS_REMEDIES_PATH", str(_catalog(tmp_path)))
    assert _gate.main() == 1
    assert "README.md: lines 1" in capsys.readouterr().out
    readme.write_text("Statues are reported; a paid plan offers a fix.\n", encoding="utf-8")
    assert _gate.main() == 0


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_live_public_docs_are_clean() -> None:
    """The shipped changelog, readme and docs share no run with the catalog when it is reachable."""
    remedies = _gate._resolve_remedies_path()
    if remedies is None:
        pytest.skip("remedy catalog not reachable")
    assert _gate.find_doc_overlap(_gate.public_doc_files(_gate.REPO_ROOT), remedies) == []

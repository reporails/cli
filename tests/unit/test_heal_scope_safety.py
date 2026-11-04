"""Scope-safety guard for `ails check --heal`.

`--heal` writes files. An implicit whole-project rewrite (no target) is refused
before any pipeline work; an explicit target, a `--dry-run` preview, or the
`--cwd` opt-in is required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_without_target_is_refused() -> None:
    """Bare `ails check --heal` (whole-project, no target) exits 2 and writes nothing.

    The guard fires before the pipeline runs, so this stays fast and ML-free.
    """
    result = runner.invoke(app, ["check", "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("dot", [".", "./"])
def test_heal_against_dot_is_refused(dot: str) -> None:
    """`ails check . --heal` resolves to the whole project root with no narrowing,
    so it is refused like a bare `--heal` (a non-empty target is not enough)."""
    result = runner.invoke(app, ["check", dot, "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_has_api_key_true_with_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--heal` is gated on auth; an env key reads as authenticated."""
    from reporails_cli.core.platform.adapters.api_key import has_api_key

    monkeypatch.setenv("AILS_API_KEY", "k")
    assert has_api_key() is True


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_has_api_key_false_when_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    """No env key + isolated HOME (no credentials) reads as anonymous — `--heal` is gated off."""
    from reporails_cli.core.platform.adapters.api_key import has_api_key

    assert has_api_key() is False


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_refusal_is_json_parseable_under_json_format() -> None:
    """Under `-f json` the refusal is a parseable JSON error, not Rich text — a
    machine consumer still gets structured output (exit 2)."""
    result = runner.invoke(app, ["check", "--heal", "-f", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "heal_requires_target"


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("second", ["CLAUDE.md", "skills"])
def test_heal_dot_plus_token_still_refused(second: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`ails check . <token> --heal`: the `.` keeps every file in scope, so a second
    narrower token must NOT rescue the whole-project rewrite — it is still refused.
    Regression: a second token previously flipped `whole_project_heal` to False.

    Runs in an isolated cwd carrying a CLAUDE.md so the second token resolves to a
    real in-tree target (a file, or the detected agent's `skills` capability);
    otherwise a "path not found" exits before the scope guard, which made this test
    depend on the runner's cwd happening to carry a root CLAUDE.md."""
    monkeypatch.chdir(tmp_path)
    Path("CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    result = runner.invoke(app, ["check", ".", second, "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_heal_leaves_files_in_heal_exclude_unchanged(tmp_path: object) -> None:
    """`ails check --heal` skips every file `heal_exclude` matches: the fixable line in
    `CLAUDE.md` is rewritten, the same line in `archive/CLAUDE.md` stays byte-identical."""
    from pathlib import Path

    from reporails_cli.core.platform.dto.diagnostics import LocationFinding, RemediationWorkflow, WorkflowLocation
    from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap
    from reporails_cli.interfaces.cli.heal import _apply_keyed_fixes

    base = Path(str(tmp_path))
    (base / ".ails").mkdir()
    (base / ".ails" / "config.yml").write_text('heal_exclude: ["archive/**"]\n', encoding="utf-8")
    (base / "archive").mkdir()
    kept, archived = base / "CLAUDE.md", base / "archive" / "CLAUDE.md"
    for path in (kept, archived):
        path.write_text("# Doc\nRun pyproject.toml here.\n", encoding="utf-8")
    archived_before = archived.read_bytes()
    atoms = tuple(
        Atom(
            line=2,
            text="Run pyproject.toml here.",
            kind="paragraph",
            charge="NEUTRAL",
            charge_value=0,
            modality="none",
            specificity="abstract",
            unformatted_code=["pyproject.toml"],
            file_path=str(path),
        )
        for path in (kept, archived)
    )
    rmap = RulesetMap(schema_version="1", embedding_model="m", generated_at="now", files=(), atoms=atoms)

    rows = tuple(LocationFinding("format", str(p), 2, 0, "code") for p in (kept, archived))
    wf = RemediationWorkflow(locations=(WorkflowLocation(1, "main", "main", "always", (), "", rows),))
    fixes = _apply_keyed_fixes(
        rmap, base, wf, dry_run=False, show_progress=False, console=None, allowed_files=[kept, archived], suppressed={}
    ).fixes

    assert archived.read_bytes() == archived_before
    assert "`pyproject.toml`" in kept.read_text(encoding="utf-8")
    assert {Path(f["file_path"]).resolve() for f in fixes} == {kept.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_bare_heal_exclude_name_drops_only_the_root_file(tmp_path: object) -> None:
    """`heal_exclude: [CLAUDE.md]` is anchored at the project root: a nested `sub/CLAUDE.md` stays writable."""
    from pathlib import Path

    from reporails_cli.core.heal.apply import allowed_set

    base = Path(str(tmp_path)).resolve()
    (base / ".ails").mkdir()
    (base / ".ails" / "config.yml").write_text("heal_exclude: [CLAUDE.md]\n", encoding="utf-8")
    (base / "sub").mkdir()
    files = [base / "CLAUDE.md", base / "sub" / "CLAUDE.md"]
    for f in files:
        f.write_text("# Doc\n", encoding="utf-8")

    assert allowed_set(base, files) == {base / "sub" / "CLAUDE.md"}


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_single_file_heal_refuses_a_symlink_to_a_file_outside_the_project(tmp_path: Path) -> None:
    """A single-file heal target is itself a symlink out of the project: its real path is not within the
    bound heal takes for a file scope (the project), so heal never writes through it."""
    from reporails_cli.core.heal.apply import heal_bound, resolved_within

    project = tmp_path / "proj"
    project.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("keep\n", encoding="utf-8")
    link = project / "CLAUDE.md"
    link.symlink_to(outside)
    inside = project / "AGENTS.md"
    inside.write_text("ok\n", encoding="utf-8")

    assert not resolved_within(link, heal_bound(link, project))
    assert resolved_within(inside, heal_bound(inside, project))
    assert resolved_within(link, heal_bound(project, project)) is False

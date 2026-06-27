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
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    monkeypatch.setenv("AILS_API_KEY", "k")
    assert has_api_key() is True


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_has_api_key_false_when_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    """No env key + isolated HOME (no credentials) reads as anonymous — `--heal` is gated off."""
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    monkeypatch.delenv("AILS_API_KEY", raising=False)
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
def test_heal_dot_plus_token_still_refused(second: str) -> None:
    """`ails check . <token> --heal`: the `.` keeps every file in scope, so a second
    narrower token must NOT rescue the whole-project rewrite — it is still refused.
    Regression: a second token previously flipped `whole_project_heal` to False.

    Runs in an isolated cwd carrying a CLAUDE.md so the second token resolves to a
    real in-tree target (a file, or the detected agent's `skills` capability);
    otherwise a "path not found" exits before the scope guard, which made this test
    depend on the runner's cwd happening to carry a root CLAUDE.md."""
    with runner.isolated_filesystem():
        Path("CLAUDE.md").write_text("# Project\n", encoding="utf-8")
        result = runner.invoke(app, ["check", ".", second, "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_mechanical_fixes_bounded_to_allowed_files(tmp_path: object) -> None:
    """Mechanical fixes write only within `allowed_files`. A mapped file outside it
    (e.g. an in-tree symlink whose real path escapes the heal target) is never
    rewritten. Regression: the mechanical pass rewrote every mapped file, bypassing
    the scope guard the additive set already passed."""
    from pathlib import Path

    from reporails_cli.core.heal.mechanical_fixers import apply_mechanical_fixes
    from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

    base = Path(str(tmp_path))
    in_scope = base / "in_scope.md"
    out_scope = base / "out_scope.md"
    in_scope.write_text("# In\nRun pyproject.toml here.\n", encoding="utf-8")
    out_scope.write_text("# Out\nRun pyproject.toml here.\n", encoding="utf-8")
    out_before = out_scope.read_text(encoding="utf-8")

    def _atom(file_path: str) -> Atom:
        return Atom(
            line=2,
            text="Run pyproject.toml here.",
            kind="paragraph",
            charge="NEUTRAL",
            charge_value=0,
            modality="none",
            specificity=0.0,
            unformatted_code=["pyproject.toml"],
            file_path=file_path,
        )

    rmap = RulesetMap(
        schema_version="1",
        embedding_model="m",
        generated_at="now",
        files=(),
        atoms=(_atom(str(in_scope)), _atom(str(out_scope))),
    )

    fixes = apply_mechanical_fixes(rmap, base, allowed_files={in_scope.resolve()})

    assert out_scope.read_text(encoding="utf-8") == out_before, "out-of-scope file was rewritten"
    assert "`pyproject.toml`" in in_scope.read_text(encoding="utf-8"), "in-scope file not healed"
    assert all(Path(f.file_path).resolve() == in_scope.resolve() for f in fixes)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_mechanical_fixes_skip_suppressed_lines(tmp_path: object) -> None:
    """Heal leaves a line the author annotated with `ails-disable-line` unmodified,
    while still fixing an unsuppressed line carrying the same token. Regression: heal
    rewrote suppressed lines because the write path ignored the suppression index."""
    from pathlib import Path

    from reporails_cli.core.heal.mechanical_fixers import apply_mechanical_fixes
    from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

    f = Path(str(tmp_path)) / "CLAUDE.md"
    f.write_text("# P\nRun pyproject.toml here.\nAlso pyproject.toml there.\n", encoding="utf-8")

    def _atom(line: int) -> Atom:
        return Atom(
            line=line,
            text="x",
            kind="paragraph",
            charge="NEUTRAL",
            charge_value=0,
            modality="none",
            specificity=0.0,
            unformatted_code=["pyproject.toml"],
            file_path=str(f),
        )

    rmap = RulesetMap(schema_version="1", embedding_model="m", generated_at="now", files=(), atoms=(_atom(2), _atom(3)))

    # Suppress line 2; line 3 stays armed.
    apply_mechanical_fixes(rmap, Path(str(tmp_path)), suppressed={f.resolve(): {2}})

    out = f.read_text(encoding="utf-8").splitlines()
    assert out[1] == "Run pyproject.toml here.", "suppressed line was rewritten"
    assert out[2] == "Also `pyproject.toml` there.", "unsuppressed line not healed"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_mechanical_fixes_skip_files_with_imports(tmp_path: object) -> None:
    """A file whose @imports expand is skipped: `atom.line` is in import-expanded space
    but the fixer edits the RAW file, so a write would target the wrong physical line.
    Regression: heal corrupted (or mis-fixed) lines on @import-bearing files."""
    from pathlib import Path

    from reporails_cli.core.heal.mechanical_fixers import apply_mechanical_fixes
    from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

    base = Path(str(tmp_path))
    (base / "frag.md").write_text("imported one\nimported two\n", encoding="utf-8")
    f = base / "CLAUDE.md"
    raw = "@frag.md\nRun pyproject.toml here.\n"
    f.write_text(raw, encoding="utf-8")

    atom = Atom(
        line=2,
        text="x",
        kind="paragraph",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity=0.0,
        unformatted_code=["pyproject.toml"],
        file_path=str(f),
    )
    rmap = RulesetMap(schema_version="1", embedding_model="m", generated_at="now", files=(), atoms=(atom,))

    fixes = apply_mechanical_fixes(rmap, base)

    assert f.read_text(encoding="utf-8") == raw, "an @import-bearing file was rewritten"
    assert fixes == []

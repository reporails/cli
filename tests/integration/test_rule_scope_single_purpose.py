"""The seven whole-file checks target only each agent's main instruction file.

`CORE:C:0019` (explicit prohibitions), `CORE:C:0022` (safety gate), `CORE:S:0002`
(section headers), `CORE:S:0016` (layered content), `CORE:S:0019` (single topic),
`CORE:E:0005` (related instructions grouped) and `CORE:C:0037` (stable-before-dynamic)
each read `match: {format: freeform}` at `f396c45` — a wildcard on every prose file
the agent owns. A single-purpose scoped file (a `.claude/rules/*.md` entry, a skill,
a nested child instruction file, a docs-only rule) is not the file these checks were
written to grade, but the wildcard match pulled it in anyway: a correctly-written
scoped rule file drew three errors and six structure findings for lacking its own
prohibition, safety directive and section headers.

`match` on all seven now narrows to the agent's primary instruction file
(`type: [main, override, agents_md, legacy_cursorrules, cross_read, system_prompt],
cardinality: [singleton, chain]`). The `cardinality` filter drops Claude's `override`
(`CLAUDE.local.md`, `cardinality: optional`) while keeping codex's `override`
(`AGENTS.override.md`, `cardinality: chain`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

SEVEN = {
    "CORE:C:0019",
    "CORE:C:0022",
    "CORE:S:0002",
    "CORE:S:0016",
    "CORE:S:0019",
    "CORE:E:0005",
    "CORE:C:0037",
}

# The checks of the seven that stay reported on a flat file: the others depend on one of these
# (`CORE:C:0022` on `CORE:C:0019`, `CORE:S:0016` on `CORE:S:0002`, `CORE:S:0019` and `CORE:E:0005`
# on `CORE:S:0016`) and are not reported beside it.
REPORTED = SEVEN - {"CORE:C:0022", "CORE:S:0016", "CORE:S:0019", "CORE:E:0005"}

# A flat, headingless, prohibition-free file — the shape every fire-set target draws
# every one of the seven on, whole-project run or scoped.
FLAT_FOUR = (
    "Run `uv run pytest` before committing.\n"
    "Use `ruff` for formatting.\n"
    "Keep modules under 300 lines.\n"
    "Follow the project conventions.\n"
)

_GOOD_MAIN = (
    "# Project\n\n"
    "## Commands\n\n"
    "Run `npm test` before committing.\n\n"
    "## Boundaries\n\n"
    "Never push to `main`.\n\n"
    "## Style\n\n"
    "Use `prettier` for formatting.\n"
)

# (main filename, main content) per agent — good, well-formed, present only to give
# each project a valid primary file so the exempt file classifies against a real
# project rather than an empty one.
MAIN_FILE_FOR: dict[str, tuple[str, str]] = {
    "claude": (
        "CLAUDE.md",
        "# Project\n\nRun `uv run pytest tests/` before every commit.\nNever edit files under `dist/`.\n",
    ),
    "cursor": ("AGENTS.md", _GOOD_MAIN),
    "copilot": (".github/copilot-instructions.md", _GOOD_MAIN),
    "codex": ("AGENTS.md", _GOOD_MAIN),
    "antigravity": ("GEMINI.md", _GOOD_MAIN),
}

# Exempt set: scoped, single-purpose files. None of the seven may fire on any of
# them, scoped or whole-project, once `match` stops wildcarding on `format: freeform`.
EXEMPT_FILES: dict[str, list[tuple[str, str]]] = {
    "claude": [
        (
            ".claude/rules/docs-context-first.md",
            '---\npaths:\n  - "docs/**"\n---\n\n'
            "When writing documentation, open with the context the reader needs, then the change.\n",
        ),
        (
            ".claude/skills/deploy/SKILL.md",
            "---\nname: deploy\ndescription: Deploy the service to staging\n---\n\n"
            + "".join(f"Run step {i} of the deploy with `make deploy-{i}`.\n" for i in range(1, 13)),
        ),
        ("packages/api/CLAUDE.md", "Use `pnpm` inside this package.\n"),
        ("CLAUDE.local.md", "Use my local Postgres on port 5433.\n"),
    ],
    "cursor": [
        (
            ".cursor/rules/docs.mdc",
            "---\ndescription: Docs writing\nglobs: docs/**\nalwaysApply: false\n---\n\n"
            "When writing documentation, open with the context the reader needs, then the change.\n",
        ),
    ],
    "copilot": [
        (
            ".github/instructions/docs.instructions.md",
            '---\napplyTo: "docs/**"\n---\n\n'
            "When writing documentation, open with the context the reader needs, then the change.\n",
        ),
    ],
    "codex": [
        ("packages/api/AGENTS.md", "Use `pnpm` inside this package.\n"),
        (
            ".agents/skills/release/SKILL.md",
            "---\nname: release\ndescription: Cut a release\n---\n\n"
            "Tag the release with `git tag vX.Y.Z` after the changelog is merged.\n",
        ),
    ],
    "antigravity": [
        (
            ".gemini/agents/reviewer.md",
            "---\nname: reviewer\ndescription: Reviews pull requests\n---\n\n"
            "Review each pull request for missing tests and report them as a list.\n",
        ),
        ("packages/api/GEMINI.md", "Use `pnpm` inside this package.\n"),
    ],
}

# Fire set: the flat, four-instruction file placed as each targeted type, including
# the non-`main` types now covered (`override`, `agents_md`, `legacy_cursorrules`,
# `cross_read`, `system_prompt`). The independent checks must still be reported on every one of these.
FIRE_FILES: dict[str, list[tuple[str, str]]] = {
    "claude": [("CLAUDE.md", "main")],
    "codex": [("AGENTS.md", "main"), ("AGENTS.override.md", "override")],
    "copilot": [(".github/copilot-instructions.md", "main"), ("AGENTS.md", "agents_md")],
    "cursor": [("AGENTS.md", "main"), (".cursorrules", "legacy_cursorrules")],
    "antigravity": [
        ("AGENTS.md", "main"),
        ("CONTEXT.md", "cross_read"),
        (".gemini/system-prompt.md", "system_prompt"),
    ],
}

AGENTS = ["claude", "codex", "copilot", "cursor", "antigravity"]


def _write(project: Path, rel: str, content: str) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _check(monkeypatch: pytest.MonkeyPatch, project: Path, *args: str) -> dict:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.requires_model
def test_exempt_set_scoped_run_draws_none_of_the_seven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: str
) -> None:
    """A scoped `ails check <file> --agent <a>` on a single-purpose file draws none of the seven.

    Reddens at `f396c45` (and at 0307802 before this unit's fix): each of these files
    is well-formed for its own purpose (a `paths:`-scoped rule, a 12-step skill, a
    nested child instruction file, a `CLAUDE.local.md` override), yet the seven
    whole-file checks wildcard on `format: freeform` and grade it as a badly-written
    main file.
    """
    project = tmp_path / "proj"
    project.mkdir()
    main_rel, main_body = MAIN_FILE_FOR[agent]
    _write(project, main_rel, main_body)
    for rel, content in EXEMPT_FILES[agent]:
        _write(project, rel, content)

    for rel, _content in EXEMPT_FILES[agent]:
        data = _check(monkeypatch, project, rel, "--agent", agent)
        fired = {f["rule"] for v in (data.get("files") or {}).values() for f in (v.get("findings") or [])}
        hit = fired & SEVEN
        assert not hit, f"{agent} {rel}: exempt file drew {sorted(hit)}"


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.requires_model
def test_fire_set_whole_project_run_reports_the_independent_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: str
) -> None:
    """A whole-project run still reports the independent checks on each of the agent's primary-file types.

    Covers every targeted type, not just `type: main` — the
    rejected fix (`match: {type: main}`) silently stops all seven on five of these
    primary files (codex `override`, copilot `agents_md`, cursor `legacy_cursorrules`,
    antigravity `cross_read` and `system_prompt`).

    Each type gets its own project (rather than sharing one with the agent's other
    target types): `CORE.*.content_check` is a `content_query` check that reports
    once per rule at `target_files[0]` (alphabetically first), not once per matching
    file — sharing a project would let one type's finding mask another's, which is a
    pre-existing `content_checker` trait this unit's `match` narrowing does not touch.
    """
    for rel, file_type in FIRE_FILES[agent]:
        project = tmp_path / file_type
        project.mkdir()
        _write(project, rel, FLAT_FOUR)

        data = _check(monkeypatch, project, ".", "--agent", agent)
        files = data.get("files") or {}
        fired = {f["rule"] for f in (files.get(rel, {}).get("findings") or [])}
        missing = REPORTED - fired
        assert not missing, f"{agent} {rel} ({file_type}): missing {sorted(missing)} (fired {sorted(fired)})"

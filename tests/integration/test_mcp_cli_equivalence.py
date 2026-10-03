"""CI equivalence gate: `ails check` and MCP `validate` produce the same finding set.

The terminal `ails check` verb and the `mcp__reporails__validate` tool are two adapters
over one shared pipeline core (`core/pipeline/`). Against the same target they must yield
the same set of `(canonical_rule_id, file, line)` finding tuples — the contract that closes
the MCP↔CLI drift class. This gate fails on any divergence.

The comparison is keyed on the canonical rule id (the `rule` field both formatters emit via
`display_rule_id`), so it cannot false-pass/fail on an unstable key. It is written to ADMIT a
third surface: add that surface's `validate`-shaped payload to the `surfaces` mapping and the
same set-equality holds it to the identical finding set — a third parallel pipeline that
reintroduced drift would redden here.

Runs offline (the server lint is stubbed to `None`) so the compared sets are the
deterministic local finding set both surfaces compute identically.

Both surfaces are invoked in whole-project mode: MCP `validate(P)` treats `P` as the
project root, and the CLI equivalent is `cd P && ails check` (no scoping path). `ails
check <dir>` with an explicit directory that differs from the cwd is a *scoped* operation
by CLI design — it skips project-aggregate checks — which is an input-parameterization
difference the equivalence contract excludes, not a coverage drift.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools, validate_targets

runner = CliRunner()

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


def _rules_installed() -> bool:
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(not _rules_installed(), reason="Rules framework not installed")


def _finding_tuples(payload: dict) -> set[tuple[str, str, int]]:
    """Extract the canonical `(rule_id, file, line)` finding tuples from a validate-shaped payload."""
    files = payload.get("files", {})
    return {
        (finding["rule"], file_path, finding["line"])
        for file_path, entry in files.items()
        for finding in entry.get("findings", [])
    }


def _cli_payload(project: Path) -> dict:
    # Whole-project mode — run from inside the project with no scoping path, matching
    # MCP `validate(project)`. An explicit `ails check <dir>` (dir != cwd) is scoped.
    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output  # 1 = findings present (default is strict-less)
    return json.loads(result.output)


def _mcp_payload(project: Path) -> dict:
    return tools.validate_tool(str(project), full=True)


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_cli_and_mcp_finding_sets_are_equal(level2_project: Path, monkeypatch) -> None:
    """The two surfaces yield identical canonical finding tuples on a shared fixture."""
    # Force offline so the compared sets are the deterministic local finding set — no server call.
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )

    # A third surface (e.g. an LSP server) joins by adding its validate-shaped payload here.
    surfaces = {
        "cli": _cli_payload(level2_project),
        "mcp": _mcp_payload(level2_project),
    }
    tuples_by_surface = {name: _finding_tuples(payload) for name, payload in surfaces.items()}

    reference_name, reference = next(iter(tuples_by_surface.items()))
    assert reference, "fixture must produce at least one finding for the gate to be meaningful"
    for name, found in tuples_by_surface.items():
        assert found == reference, (
            f"{name} finding set diverges from {reference_name}:\n"
            f"  only in {name}: {sorted(found - reference)}\n"
            f"  only in {reference_name}: {sorted(reference - found)}"
        )


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_cli_and_mcp_agree_on_a_multi_agent_project_with_unowned_files(tmp_path: Path, monkeypatch) -> None:
    """`validate` is the paid path and must never diverge from `ails check`. A project
    where Claude natively owns some files and a
    non-distinctive cross-reading agent's OWN cross-read reaches files no agent's own
    namespace claims (`.agents/skills/**`, a nested `AGENTS.md`) must score the exact same
    `(rule, file, line)` triples on both surfaces -- before this fix, MCP ran ONE
    `effective_agent` pass over every file (over-applying Claude's rules to the unowned
    files, or under-applying them, depending on which agent won the label), while the CLI
    partitioned by native ownership (`core.pipeline.mapping.agent_file_pairs`)."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nUse `ruff format` on every changed Python file.\n", encoding="utf-8"
    )
    for base in (".claude/skills", ".agents/skills"):
        skill_dir = project / base / "alpha"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: alpha\ndescription: The alpha skill\n---\n\nRun `make alpha` after tests pass.\n",
            encoding="utf-8",
        )
    (project / "plugin" / "dashboard").mkdir(parents=True)
    (project / "plugin" / "dashboard" / "AGENTS.md").write_text(
        "# Dashboard subproject\n\nBefore writing route handlers, read the framework guide.\n",
        encoding="utf-8",
    )

    cli_tuples = _finding_tuples(_cli_payload(project))
    mcp_tuples = _finding_tuples(_mcp_payload(project))

    assert cli_tuples, "fixture must produce at least one finding for the gate to be meaningful"
    assert cli_tuples == mcp_tuples, (
        f"MCP diverges from CLI:\n  only in mcp: {sorted(mcp_tuples - cli_tuples)}\n"
        f"  only in cli: {sorted(cli_tuples - mcp_tuples)}"
    )


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_cli_and_mcp_agree_on_a_single_file_target(level2_project: Path, monkeypatch) -> None:
    """A single-file target must agree between surfaces, and must not carry
    project-aggregate mechanical findings (e.g. `CORE:S:0010` file-count-bounds) that only
    the whole-project scan runs."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    target_file = level2_project / "CLAUDE.md"

    cwd = os.getcwd()
    os.chdir(level2_project)
    try:
        result = runner.invoke(app, ["check", "CLAUDE.md", "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output
    cli_payload = json.loads(result.output)
    mcp_payload = tools.validate_tool(str(target_file), full=True)

    cli_tuples = _finding_tuples(cli_payload)
    mcp_tuples = _finding_tuples(mcp_payload)
    assert cli_tuples == mcp_tuples
    assert not any(rule_id == "CORE:S:0010" for rule_id, _file, _line in mcp_tuples), (
        "a single-file validate must not carry the project-aggregate file-count-bounds rule"
    )


def _isolate_global_config(monkeypatch, tmp_path: Path) -> None:
    """Point the global config at a path that can't exist, so the machine's real
    `~/.reporails/config.yml` (`default_agent`, `tier`, ...) never leaks into a fixture
    project that doesn't set its own `.ails/config.yml` value -- these tests assert exact
    empty-project / unknown-agent shapes that a stray global `default_agent` would mask."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_config_path",
        lambda: tmp_path / "unused-global-config.yml",
    )


@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_agents_md_only_project_under_misconfigured_default_agent_matches_cli(tmp_path, monkeypatch) -> None:
    """An AGENTS.md-only project under `default_agent: claude`, with Claude
    Code set to read CLAUDE.md files only, comes up with zero files to lint after
    agent-filtering on BOTH surfaces. MCP must report the CLI's own benign empty shape, not a
    hard `{"error": "No instruction files found"}` that regresses a previously-clean project."""
    _isolate_global_config(monkeypatch, tmp_path)
    settings = Path.home() / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        json.dumps({"pluginConfigs": {"agents-md@builtin": {"options": {"instructionFiles": "claude-md"}}}}),
        encoding="utf-8",
    )
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / "AGENTS.md").write_text(
        "# Agents\n\nGuidance for agents working in this repository.\n", encoding="utf-8"
    )
    (project / ".ails" / "config.yml").write_text("default_agent: claude\n", encoding="utf-8")

    cli_payload = _cli_payload(project)
    mcp_payload = tools.validate_tool(str(project), full=True)

    assert "error" not in mcp_payload, mcp_payload
    # One envelope on BOTH surfaces: the normal-run shape over an empty finding set.
    # `elapsed_ms` is a CLI-only wall-clock echo, so it is dropped before comparing.
    assert {k: v for k, v in cli_payload.items() if k != "elapsed_ms"} == mcp_payload
    assert mcp_payload["files"] == {}
    assert mcp_payload["level"] == "L0"
    assert "violations" not in mcp_payload


@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_typo_default_agent_surfaces_as_unknown_agent_on_both_surfaces(tmp_path, monkeypatch) -> None:
    """A typo'd `default_agent: cluade` — the CLI exits with "Unknown agent:
    cluade" via `_validate_agent` before ever discovering files; MCP must surface the same
    fact structurally instead of masking the misconfiguration as "No instruction files"."""
    _isolate_global_config(monkeypatch, tmp_path)
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Claude\n\nSome guidance for Claude Code.\n", encoding="utf-8")
    (project / ".ails" / "config.yml").write_text("default_agent: cluade\n", encoding="utf-8")

    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 2
    assert "Unknown agent: cluade" in result.output

    mcp_payload = tools.validate_tool(str(project), full=True)
    assert mcp_payload.get("error") == "Unknown agent: cluade"
    assert "known_agents" in mcp_payload


@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_rules_only_tree_with_no_distinctive_agent_matches_cli(tmp_path, monkeypatch) -> None:
    """A `.claude/rules/*.md`-only tree (no main `CLAUDE.md`) with no `default_agent` set
    used to resolve to the empty agent id on both surfaces, because Copilot's cross-read of
    `.claude/**` counted as equally "distinctive" and the mixed result collapsed to
    `generic`. With the cross-read exclusion in place, Claude alone owns
    `.claude/rules/style.md` natively and stays distinctive, so both surfaces now resolve to
    `claude` and take the NORMAL (non-empty-instruction-files) run path for the first time
    on this fixture. That path genuinely attempts a server round-trip; offline, MCP's
    `_attach_funnel` carries the resulting `FunnelError` as a top-level `funnel` object for
    MCP tool consumers, while the CLI's text renderer shows the identical information as an
    on-screen CTA instead of a JSON key (`_attach_funnel`'s own docstring: "mirrors it for
    MCP consumers") -- a pre-existing, documented asymmetry this fixture never exercised
    before because the old mixed-resolution behavior short-circuited it to a degenerate
    empty shape. MCP must still match the CLI on every key BOTH surfaces carry."""
    _isolate_global_config(monkeypatch, tmp_path)
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nStyle guidance for agents working in this repository.\n", encoding="utf-8"
    )

    cli_payload = _cli_payload(project)
    mcp_payload = tools.validate_tool(str(project), full=True)

    assert "error" not in mcp_payload, mcp_payload
    # `elapsed_ms` is a CLI-only wall-clock echo; `funnel` is an intentional MCP-only key
    # (CLI renders the same funnel CTA as on-screen text, never as a JSON field) -- both are
    # dropped before comparing the envelope both surfaces actually share.
    cli_comparable = {k: v for k, v in cli_payload.items() if k != "elapsed_ms"}
    mcp_comparable = {k: v for k, v in mcp_payload.items() if k != "funnel"}
    assert cli_comparable == mcp_comparable
    # Claude now owns `.claude/rules/style.md` natively and its rules genuinely run --
    # `CORE:S:0010` (the whole-project-scope "shape" rule a lone-file project always
    # trips) fires on both surfaces, which is the fix working, not a regression: the old
    # empty-`files`/`L0` shape was the mixed-resolution bug's own symptom.
    assert (
        mcp_payload["files"]
        == cli_payload["files"]
        == {".claude/rules/style.md": mcp_payload["files"][".claude/rules/style.md"]}
    )
    assert any(f["rule"] == "CORE:S:0010" for f in mcp_payload["files"][".claude/rules/style.md"]["findings"])
    assert "violations" not in mcp_payload


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_generic_scan_import_reached_file_set_matches_cli(tmp_path, monkeypatch) -> None:
    """With `generic_scanning: true` and an `@`-import in the main instruction
    file, the import-reached file must be folded into BOTH surfaces' scored file set."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")
    (project / "docs").mkdir()
    (project / "docs" / "arch.md").write_text(
        "# Architecture\n\nThe system is organized into a few core modules.\n", encoding="utf-8"
    )
    (project / "CLAUDE.md").write_text(
        "# Project\n\n@docs/arch.md\n\n## Constraints\n\n- MUST follow the architecture doc\n",
        encoding="utf-8",
    )

    cli_payload = _cli_payload(project)
    mcp_payload = tools.validate_tool(str(project), full=True)

    assert set(cli_payload.get("files", {})) == set(mcp_payload.get("files", {}))
    assert "docs/arch.md" in mcp_payload.get("files", {})


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_a_target_resolves_to_the_files_ails_check_checks(tmp_path: Path, monkeypatch) -> None:
    """`validate(targets=["skills"])` keeps the locations of exactly the files `ails check skills`
    checks: both read the token through one resolver, against the same project."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    _isolate_global_config(monkeypatch, tmp_path)
    project = tmp_path / "proj"
    (project / ".claude" / "agents").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n\nRun `pytest` before committing.\n")
    (project / ".claude" / "agents" / "reviewer.md").write_text("# Reviewer\n\nReview the diff.\n")
    for name in ("backlog", "release"):
        skill = project / ".claude" / "skills" / name / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(f"# {name}\n\nUse this skill for {name} work.\n")

    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", "skills", "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output
    cli_files = {str((project / rel).resolve()) for rel in json.loads(result.output)["files"]}

    resolved = validate_targets.resolve_validate_targets(("skills",), project.resolve())
    assert isinstance(resolved, tuple), resolved
    files, dirs = resolved
    assert not dirs
    assert (
        {str(p) for p in files}
        == cli_files
        == {str((project / ".claude" / "skills" / n / "SKILL.md").resolve()) for n in ("backlog", "release")}
    )


def _two_agent_project(tmp_path: Path, body: str) -> Path:
    """A project Claude and Codex both claim: one file each, plus each agent's marker."""
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / ".codex").mkdir()
    (project / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (project / ".codex" / "config.toml").write_text('model = "x"\n', encoding="utf-8")
    (project / "CLAUDE.md").write_text(body, encoding="utf-8")
    (project / "AGENTS.md").write_text(body, encoding="utf-8")
    return project


def _rule_counts(payload: dict, rule_id: str) -> int:
    return sum(1 for rule, _file, _line in _finding_tuples(payload) if rule == rule_id)


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_two_agent_project_judges_project_wide_rules_over_all_files(tmp_path: Path, monkeypatch) -> None:
    """Two instruction files owned by two agents satisfy the two-file minimum on both surfaces.
    The core total-size limit judges the files no agent's own size rule replaces, once; Codex's
    own size rule judges the Codex file."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    small = _two_agent_project(tmp_path / "small", "# Proj\n\nRun `make test` before every commit.\n")
    cli_small, mcp_small = _cli_payload(small), _mcp_payload(small)
    assert _finding_tuples(cli_small) == _finding_tuples(mcp_small)
    assert _rule_counts(cli_small, "CORE:S:0010") == 0
    assert _rule_counts(mcp_small, "CORE:S:0010") == 0

    big = _two_agent_project(tmp_path / "big", "# Proj\n\n" + "Run `make test` before every commit.\n" * 3000)
    cli_big, mcp_big = _cli_payload(big), _mcp_payload(big)
    assert _finding_tuples(cli_big) == _finding_tuples(mcp_big)
    for payload in (cli_big, mcp_big):
        assert _rule_counts(payload, "CORE:E:0001") == 1
        assert _rule_counts(payload, "CODEX:E:0001") == 1
        assert {f for r, f, _l in _finding_tuples(payload) if r == "CORE:E:0001"} == {"CLAUDE.md"}

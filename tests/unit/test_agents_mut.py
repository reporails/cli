"""Mutation-kill tests for core.discovery.agents — config parsing, registry
build, shared-file disambiguation, and agent resolution.

Each test feeds an input whose correct output a specific injected operator bug
would change (a wrong bucket route, a flipped name-fallback, a mis-thresholded
shared-file count, a wrong resolution flag), so the assertion reddens when that
bug returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import reporails_cli.core.discovery.agents as agents_mod
from reporails_cli.core.discovery.agents import (
    AgentType,
    DetectedAgent,
    _build_agent_registry,
    _disambiguate_shared_files,
    _distinctive_agents,
    _extract_properties,
    _parse_agent_config,
    detect_single_agent,
    resolve_agent,
)


def _at(agent_id: str) -> AgentType:
    return AgentType(
        id=agent_id,
        name=agent_id.title(),
        instruction_patterns=(),
        config_patterns=(),
        rule_patterns=(),
    )


def _da(
    agent_id: str,
    instruction_files: list[str],
    rule_files: list[str] | None = None,
    config_files: list[str] | None = None,
) -> DetectedAgent:
    return DetectedAgent(
        agent_type=_at(agent_id),
        instruction_files=[Path(f) for f in instruction_files],
        rule_files=[Path(f) for f in (rule_files or [])],
        config_files=[Path(f) for f in (config_files or [])],
    )


# ── _extract_properties (L64) ────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extract_properties_keeps_only_known_keys() -> None:
    """A v0.5.0 flattened spec keeps only recognised property keys
    (kills `k in prop_keys and v is not None` -> `or`)."""
    props = _extract_properties({"format": "freeform", "scope": "global", "bogus": "x"})
    assert props == {"format": "freeform", "scope": "global"}
    assert "bogus" not in props


# ── _parse_agent_config name fallback (L95) ──────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_parse_uses_explicit_name() -> None:
    """An explicit `name` wins over the agent id (kills L95 first `or` -> `and`)."""
    data = {"agent": "myagent", "name": "Foo", "file_types": {"m": {"patterns": ["**/CLAUDE.md"]}}}
    at = _parse_agent_config(data)
    assert at is not None
    assert at.name == "Foo"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_parse_falls_back_to_agent_id_when_name_empty() -> None:
    """An empty `name` falls back to the agent id (kills L95 second `or` -> `and`)."""
    data = {"agent": "myagent", "name": "", "file_types": {"m": {"patterns": ["**/CLAUDE.md"]}}}
    at = _parse_agent_config(data)
    assert at is not None
    assert at.name == "myagent"


# ── _parse_agent_config guard (L97) ──────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_parse_returns_none_on_invalid_config() -> None:
    """Missing agent or non-dict file_types → None (kills L97 `or` -> `and`)."""
    assert _parse_agent_config({"file_types": {"m": {"patterns": ["**/CLAUDE.md"]}}}) is None
    assert _parse_agent_config({"agent": "x", "file_types": "not-a-dict"}) is None


# ── bucket routing (L113, L117, L121) ────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_instruction_bucket_populates_instruction_patterns() -> None:
    """An instruction file_type feeds instruction_patterns (kills L113 == -> !=)."""
    data = {
        "agent": "ag",
        "file_types": {"main": {"patterns": ["**/CLAUDE.md"], "format": "freeform", "scope": "global"}},
    }
    at = _parse_agent_config(data)
    assert at is not None
    assert "CLAUDE.md" in at.instruction_patterns


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_bucket_populates_rule_patterns() -> None:
    """A path_scoped file_type feeds rule_patterns + directory_patterns (kills L117 == -> !=)."""
    data = {
        "agent": "ag",
        "file_types": {"r": {"patterns": [".claude/rules/**/*.md"], "scope": "path_scoped"}},
    }
    at = _parse_agent_config(data)
    assert at is not None
    assert at.rule_patterns == (".claude/rules/**/*.md",)
    assert ("rules", ".claude/rules") in at.directory_patterns


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_pattern_without_dir_prefix_adds_no_none() -> None:
    """A wildcard-leading rule pattern yields no dir pair — none is appended
    (kills L121 `pair and pair not in ...` -> `or`)."""
    data = {
        "agent": "ag",
        "file_types": {"r": {"patterns": ["*.mdc"], "scope": "path_scoped"}},
    }
    at = _parse_agent_config(data)
    assert at is not None
    assert at.directory_patterns == ()
    assert None not in at.directory_patterns


# ── _build_agent_registry guards (L144, L152) ────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_registry_empty_when_no_rules_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """No rules path → empty registry, no crash (kills L144 `or` -> `and`)."""
    import reporails_cli.core.platform.config.bootstrap as bootstrap

    monkeypatch.setattr(bootstrap, "get_rules_path", lambda: None)
    assert _build_agent_registry() == {}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_registry_skips_non_dict_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A config.yml that loads as a list is skipped, not parsed (kills L152 `or` -> `and`)."""
    import reporails_cli.core.platform.config.bootstrap as bootstrap

    (tmp_path / "badagent").mkdir()
    (tmp_path / "badagent" / "config.yml").write_text("- a\n- b\n")
    (tmp_path / "goodagent").mkdir()
    (tmp_path / "goodagent" / "config.yml").write_text(
        "agent: goodagent\nfile_types:\n  m:\n    patterns: ['**/CLAUDE.md']\n"
    )
    monkeypatch.setattr(bootstrap, "get_rules_path", lambda: tmp_path)
    registry = _build_agent_registry()
    assert "goodagent" in registry


# ── detect_single_agent repo scope (L376) ───────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_detect_single_agent_scans_repo_scoped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Single-agent detection scans repo-scoped so a global ~/ marker cannot
    hijack it (kills L376 `repo_scoped=True` -> False)."""
    captured: dict = {}

    def _spy(target, agent_id, rules_paths, **kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(agents_mod, "_discover_from_config", _spy)
    detect_single_agent(tmp_path, "claude")
    assert captured.get("repo_scoped") is True


# ── _disambiguate_shared_files (L446, L459) ──────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_shared_by_exactly_two_agents_is_shared() -> None:
    """A file claimed by exactly two agents counts as shared → both non-distinctive
    agents drop (kills L446 `count >= 2` -> `count > 2`)."""
    shared_file = "AGENTS.md"
    a = _da("cursor", [shared_file])
    b = _da("copilot", [shared_file])
    result = _disambiguate_shared_files([a, b])
    assert result == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agent_with_distinctive_file_survives() -> None:
    """An agent with a non-shared instruction file is kept even with no rule/config
    files (kills L459 `or` -> `and`)."""
    a = _da("cursor", ["AGENTS.md", ".cursor/rules.md"])  # AGENTS.md shared, .cursor distinctive
    b = _da("copilot", ["AGENTS.md"])
    result = _disambiguate_shared_files([a, b])
    ids = {d.agent_type.id for d in result}
    assert "cursor" in ids


# ── resolve_agent flags (L493, L496, L498, L499) ─────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agent_kept_by_rule_files_alone() -> None:
    """An agent with only shared instruction files but its own rule files is kept
    (kills L459 second `or` -> `and`: `rule_files or config_files` must not become
    `rule_files and config_files`)."""
    a = _da("cursor", ["AGENTS.md"], rule_files=[".cursor/rules/x.md"])  # shared instr, own rule file
    b = _da("copilot", ["AGENTS.md"])
    result = _disambiguate_shared_files([a, b])
    ids = {d.agent_type.id for d in result}
    assert "cursor" in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_explicit_agent_not_assumed_or_mixed() -> None:
    """An explicit agent returns (agent, assumed=False, mixed=False) (kills L493 x2)."""
    assert resolve_agent("claude", []) == ("claude", False, False)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_empty_returns_all_false() -> None:
    """No agents, none detected → ('', False, False) (kills L499 x2)."""
    assert resolve_agent("", []) == ("", False, False)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_single_distinctive_is_assumed_not_mixed() -> None:
    """One distinctive agent → (id, assumed=True, mixed=False) (kills L496 False->True)."""
    detected = [_da("cursor", ["AGENTS.md"])]
    assert resolve_agent("", detected) == ("cursor", True, False)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_two_distinctive_is_mixed_not_assumed() -> None:
    """Two distinctive agents → ('', assumed=False, mixed=True) (kills L498 False->True)."""
    detected = [_da("cursor", ["a.md"]), _da("copilot", ["b.md"])]
    assert resolve_agent("", detected) == ("", False, True)


# ── Cross-read-only agents are not distinctive ────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_distinctive_agents_counts_rule_files_against_generic() -> None:
    """An agent whose only instruction file is shared with generic, but which also has its
    own rule file, is still distinctive: the instruction-files-only subset check dropped
    Cursor in the AGENTS.md-plus-`.cursor/rules` overlap fixture, since it never looked at
    `rule_files` the way `_disambiguate_shared_files` does."""
    target = Path("/proj")
    cursor = _da("cursor", ["/proj/AGENTS.md"], rule_files=["/proj/.cursor/rules/always.mdc"])
    generic = _da("generic", ["/proj/AGENTS.md"])
    distinctive = _distinctive_agents([cursor, generic], target)
    assert {d.agent_type.id for d in distinctive} == {"cursor"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_cross_read_only_agent_not_distinctive() -> None:
    """Copilot's cross-read of Claude's `.claude/rules` / `.claude/skills` namespace (declared
    in copilot's own config for cross-agent compatibility) does not make Copilot distinctive
    when Claude -- the namespace's real owner -- is also detected here; this guards against a
    fresh Claude project resolving as mixed claude+copilot and falling back to the generic
    ruleset, dropping CORE:G:0002 and every Claude-specific rule."""
    target = Path("/proj")
    claude = _da(
        "claude",
        ["/proj/CLAUDE.md", "/proj/.claude/skills/deploy/SKILL.md"],
        rule_files=["/proj/.claude/rules/style.md"],
    )
    copilot = _da(
        "copilot",
        ["/proj/.claude/skills/deploy/SKILL.md"],
        rule_files=["/proj/.claude/rules/style.md"],
    )
    distinctive = _distinctive_agents([claude, copilot], target)
    assert {d.agent_type.id for d in distinctive} == {"claude"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_agent_drops_cross_read_copilot_end_to_end() -> None:
    """End to end: `resolve_agent` returns Claude cleanly, not mixed, for this fixture shape
    (`CLAUDE.md` + `.claude/rules/style.md` + `.claude/skills/deploy/SKILL.md`)."""
    target = Path("/proj")
    claude = _da(
        "claude",
        ["/proj/CLAUDE.md", "/proj/.claude/skills/deploy/SKILL.md"],
        rule_files=["/proj/.claude/rules/style.md"],
    )
    copilot = _da(
        "copilot",
        ["/proj/.claude/skills/deploy/SKILL.md"],
        rule_files=["/proj/.claude/rules/style.md"],
    )
    assert resolve_agent("", [claude, copilot], target) == ("claude", True, False)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_distinctive_agents_without_target_skips_cross_read_check() -> None:
    """No `target` (a caller with no project root on hand) still runs the generic-subset
    check, but skips the cross-read check rather than erroring -- backward compatible with
    every existing 2-arg caller of `_distinctive_agents` / `resolve_agent`."""
    copilot = _da("copilot", ["/proj/.claude/skills/deploy/SKILL.md"])
    distinctive = _distinctive_agents([copilot])
    assert {d.agent_type.id for d in distinctive} == {"copilot"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_cross_reader_of_claude_and_a_shared_standard_still_excluded() -> None:
    """Regression: Copilot cross-reads BOTH Claude's `.claude/**`
    namespace AND the shared, nobody's-specific `.agents/skills/**` standard, with no
    `.github/copilot-instructions.md` (or any other) file of its own. The mixed evidence
    (one real cross-read + one neutral shared surface) must not save Copilot from
    exclusion -- the `.agents/skills/**` files resolve to `generic`, not to Copilot, so
    they never establish Copilot's own distinctiveness. Only Claude stays distinctive
    (a project mixing `.claude/{rules,skills}` + `.agents/skills`, no
    `CLAUDE.md`, no `AGENTS.md`, no Copilot main file)."""
    target = Path("/proj")
    claude = _da(
        "claude",
        ["/proj/.claude/skills/a/SKILL.md"],
        rule_files=["/proj/.claude/rules/x.md"],
    )
    copilot = _da(
        "copilot",
        [
            "/proj/.claude/skills/a/SKILL.md",  # cross-read of Claude's own namespace
            "/proj/.agents/skills/a/SKILL.md",  # the shared, nobody's-specific standard
        ],
        rule_files=["/proj/.claude/rules/x.md"],  # cross-read of Claude's own namespace
    )
    distinctive = _distinctive_agents([claude, copilot], target)
    assert {d.agent_type.id for d in distinctive} == {"claude"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_copilots_own_github_directory_is_native_despite_the_namespace_name_mismatch() -> None:
    """Copilot's real main file lives at `.github/copilot-instructions.md` -- the
    directory name ("github") does not match the agent id ("copilot") the way it does
    for Claude/Cursor/Codex. The namespace-alias map must still read this as Copilot's
    own native evidence, not as an unowned or foreign namespace, even while Copilot also
    cross-reads Claude's `.claude/rules/**`."""
    target = Path("/proj")
    claude = _da("claude", [], rule_files=["/proj/.claude/rules/x.md"])
    copilot = _da(
        "copilot",
        ["/proj/.github/copilot-instructions.md"],
        rule_files=["/proj/.claude/rules/x.md"],
    )
    distinctive = _distinctive_agents([claude, copilot], target)
    # Both stay distinctive: Claude owns `.claude/rules` natively, and Copilot's own
    # `.github/copilot-instructions.md` is native evidence too, despite the directory-vs-id
    # name mismatch -- Copilot's cross-read of the SAME `.claude/rules` file does not cost
    # it anything once it already has native evidence of its own.
    assert {d.agent_type.id for d in distinctive} == {"claude", "copilot"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_partition_by_native_owner_attributes_a_nested_main_file_to_its_sole_claimant() -> None:
    """Regression: `packages/web/CLAUDE.md` sits neither at the project
    root (`_is_project_root_file` needs exactly one path part) nor inside `.claude/`
    (`_agent_namespace` needs a dot-directory), so the old namespace/root-file tie-break
    routed it to the core-only ruleset even though Claude is the ONLY agent that ever
    claims a `CLAUDE.md`-shaped file. A file only one detected agent claims at all is
    unambiguous native evidence for that agent the moment it stays distinctive -- the
    namespace/root-file tie-break is only needed once multiple agents claim the SAME
    path (a shared standard like root `AGENTS.md`)."""
    from reporails_cli.core.discovery.agent_discovery import partition_by_native_owner

    target = Path("/proj")
    claude = _da(
        "claude",
        ["/proj/CLAUDE.md", "/proj/packages/web/CLAUDE.md"],
    )
    owner_by_path = partition_by_native_owner([claude], target)
    assert owner_by_path["/proj/packages/web/CLAUDE.md"] == "claude"
    assert owner_by_path["/proj/CLAUDE.md"] == "claude"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_partition_by_native_owner_still_falls_back_to_generic_on_a_shared_standard() -> None:
    """The exact `cs` shape this guards: Copilot's only claims are a cross-read of
    Claude's own `.claude/skills/**` namespace and a nested `AGENTS.md` (the shared,
    nobody's-specific standard). Copilot is the sole claimant of the `AGENTS.md` path,
    but it has no native evidence of its own anywhere, so it never becomes distinctive
    (per `test_cross_reader_of_claude_and_a_shared_standard_still_excluded`) -- the
    single-claimant shortcut must not hand it the file just because nobody else in this
    call also claims that exact path. Guards the shortcut against over-reaching past
    what it is meant to fix (an UNAMBIGUOUS single-agent file pattern like `CLAUDE.md`,
    not an ambiguous shared standard that merely happens to have one claimant here)."""
    from reporails_cli.core.discovery.agent_discovery import partition_by_native_owner

    target = Path("/proj")
    claude = _da("claude", ["/proj/.claude/skills/a/SKILL.md"])
    copilot = _da(
        "copilot",
        [
            "/proj/.claude/skills/a/SKILL.md",  # cross-read of Claude's own namespace
            "/proj/plugin/dashboard/AGENTS.md",  # the shared, nobody's-specific standard
        ],
    )
    owner_by_path = partition_by_native_owner([claude, copilot], target)
    assert owner_by_path["/proj/plugin/dashboard/AGENTS.md"] == "generic"
    assert owner_by_path["/proj/.claude/skills/a/SKILL.md"] == "claude"

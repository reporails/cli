"""Fixture scaffolding for the rule-test harness.

Builds the minimal on-disk structure a rule's mechanical checks need to pass
(pass fixtures) or the targeted breakage that makes them fail (fail fixtures),
so a rule's own ``tests/pass`` and ``tests/fail`` directories don't have to
carry scaffold files the check would otherwise demand.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.models import Check, FileTypeDeclaration


def _glob_to_concrete(pattern: str) -> str:
    """Convert a glob pattern to a concrete file path for scaffolding.

    Examples:
        "**/*.md" → "scaffold.md"
        ".claude/skills/**" → ".claude/skills/scaffold"
        ".claude/rules/**/*.md" → ".claude/rules/scaffold.md"
    """
    # Strip leading ./
    clean = pattern.removeprefix("./")
    parts = clean.split("/")
    concrete: list[str] = []
    for part in parts:
        if part == "**":
            continue
        if "*" in part:
            # Replace glob with scaffold filename, preserving extension
            ext = ""
            if "." in part:
                ext = part[part.rindex(".") :]
                if "*" in ext:
                    ext = ".md"
            concrete.append(f"scaffold{ext}")
        else:
            concrete.append(part)
    return "/".join(concrete) if concrete else "scaffold.md"


_SCAFFOLDABLE_CHECKS: dict[str, str] = {
    "file_exists": "file",
    "glob_match": "file",
    "directory_exists": "dir",
    "glob_count": "glob_count",
    "file_count": "glob_count",
    "git_tracked": "git_marker",
    "file_tracked": "git_marker",
    "file_absent": "file_removal",
}


def _collect_scaffold_actions(
    checks: list[Check],
) -> list[tuple[str, dict[str, Any]]]:
    """Extract scaffoldable actions from mechanical checks."""
    actions: list[tuple[str, dict[str, Any]]] = []
    for check in checks:
        if check.type != "mechanical":
            continue
        check_name = check.check or ""
        action_type = _SCAFFOLDABLE_CHECKS.get(check_name)
        if action_type:
            actions.append((action_type, check.args or {}))
    return actions


def _apply_scaffold_action(
    action_type: str,
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Apply a single scaffold action to the temp directory."""
    if action_type == "file":
        _scaffold_file(args, tmp_dir, file_types)
    elif action_type == "dir":
        path = str(args.get("path", ""))
        target = tmp_dir / path
        if not target.is_dir():
            target.mkdir(parents=True, exist_ok=True)
    elif action_type == "glob_count":
        _scaffold_glob_count(args, tmp_dir)
    elif action_type == "file_removal":
        _scaffold_file_removal(args, tmp_dir)
    elif action_type == "git_marker":
        marker = tmp_dir / ".git_marker"
        if not marker.exists() and not (tmp_dir / ".git").exists():
            marker.touch()


def _scaffold_file(
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Scaffold a single file for file_exists/glob_match checks.

    Skips creation when a file already in the fixture satisfies the
    pattern. The fixture's own file (e.g. `example.md` for a `**/*.md`
    check) already carries the content another check in the same rule
    chain expects (frontmatter, a required key); scaffolding a second,
    empty file unconditionally leaves a spurious empty sibling that a
    per-file check (e.g. `frontmatter_present`) then reports on.
    """
    path_pattern = str(args.get("path", ""))
    if path_pattern:
        if any(True for _ in tmp_dir.glob(path_pattern)):
            return
        concrete = _glob_to_concrete(path_pattern)
    else:
        # Use first file type pattern as fallback
        if not file_types:
            return
        fallback_pattern = file_types[0].patterns[0] if file_types[0].patterns else ""
        if fallback_pattern and any(True for _ in tmp_dir.glob(fallback_pattern)):
            return
        concrete = _glob_to_concrete(fallback_pattern or "scaffold.md")
    target = tmp_dir / concrete
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


def _scaffold_glob_count(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Scaffold files for glob_count/file_count checks."""
    raw_pattern = str(args.get("pattern", "**/*"))
    min_count = int(args.get("min", 1))
    existing = list(tmp_dir.glob(raw_pattern))
    needed = max(0, min_count - len(existing))
    for i in range(needed):
        concrete = _glob_to_concrete(raw_pattern)
        base, ext = concrete.rsplit(".", 1) if "." in concrete else (concrete, "")
        name = f"{base}_{i}.{ext}" if ext else f"{base}_{i}"
        target = tmp_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


def _agent_main_filename(file_types: list[FileTypeDeclaration]) -> str | None:
    """The concrete filename the target agent's `main` file type resolves to.

    Returns None when the agent config declares no `main` file type or the
    declaration carries no patterns.
    """
    for ft in file_types:
        if ft.name == "main" and ft.patterns:
            return _glob_to_concrete(ft.patterns[0])
    return None


def _scaffold_main_filename(
    fixture_root: Path,
    file_types: list[FileTypeDeclaration],
) -> Path | None:
    """Rename a fixture's root `CLAUDE.md` to the target agent's own main filename.

    CORE fixtures are authored once, on disk as `CLAUDE.md` — the harness's
    agent-agnostic convention. Run unmodified under a non-Claude `--agent`,
    such a fixture never classifies as the agent's `main` file type (e.g.
    Codex and Cursor expect `AGENTS.md`, Copilot expects
    `.github/copilot-instructions.md`), so every check targeting `main`
    reports a false failure that has nothing to do with the rule under test.

    Returns a scaffolded copy with the rename applied, or None when the
    fixture carries no root `CLAUDE.md` or the target agent's own main
    filename already is `CLAUDE.md` (Claude itself, or an agent config with
    no `main` declaration).
    """
    source = fixture_root / "CLAUDE.md"
    if not source.is_file():
        return None
    concrete = _agent_main_filename(file_types)
    if not concrete or concrete == "CLAUDE.md":
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_agent_main_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)
    dest = tmp_dir / concrete
    dest.parent.mkdir(parents=True, exist_ok=True)
    (tmp_dir / "CLAUDE.md").rename(dest)
    return tmp_dir


def _agent_recognizes_claude_rules(file_types: list[FileTypeDeclaration]) -> bool:
    """Whether the target agent's own config already classifies `.claude/rules/**` paths.

    Claude declares this path as its own scoped-rule directory; Copilot
    declares it too, for cross-agent compatibility (VS Code reads
    `.claude/rules/` alongside its native `.github/instructions/`). Neither
    needs the relocation `_scaffold_scoped_rule_file` below performs.
    """
    return any(".claude/rules" in p for ft in file_types for p in ft.patterns)


def _agent_markdown_rules_dir(file_types: list[FileTypeDeclaration]) -> str | None:
    """Directory prefix of the target agent's own markdown-capable `rules` file type.

    Returns None when the agent declares no `rules` file type, or its
    patterns carry no markdown-flavored (`freeform`/`frontmatter`) format —
    Codex's `rules` type, for example, is Starlark (`format: schema_validated`),
    a different artifact class a markdown scoped-rule fixture cannot stand in for.
    """
    for ft in file_types:
        if ft.name != "rules":
            continue
        fmt = ft.properties.get("format")
        formats = fmt if isinstance(fmt, list) else [fmt] if fmt else []
        if not any(f in ("freeform", "frontmatter") for f in formats):
            return None
        for pattern in ft.patterns:
            if pattern.endswith(".md"):
                prefix = pattern.split("**")[0].rstrip("/")
                if prefix:
                    return prefix
    return None


def _scaffold_scoped_rule_file(
    fixture_root: Path,
    file_types: list[FileTypeDeclaration],
    checks: list[Check],
) -> Path | None:
    """Relocate a CORE fixture's `.claude/rules/**` file to the target agent's own layout.

    CORE fixtures author their scoped-rule-file case once, on disk under
    `.claude/rules/` — Claude's own convention, which Copilot also recognizes.
    Run unmodified under an agent with a different scoped-rule directory
    (Cursor's `.cursor/rules/`), the fixture file never classifies at all, so
    a check targeting it sees no files and reports no violation — a false
    pass on a fail fixture, unrelated to the rule under test. The relocation
    always preserves the fixture's own filename, so a rule checking the
    filename itself (`filename_matches_pattern`) still sees the exact name
    it was written to judge.

    An agent with no markdown scoped-rule surface at all (Codex's
    Starlark-only `.codex/rules/*.rules`, or Antigravity, which declares no
    `rules` type) has no directory where an arbitrarily-named file classifies
    as an instruction file — only exact main-filename matches do. For a rule
    whose checks don't depend on the filename's own value (no
    `filename_matches_pattern`), the file is relocated next to a copy of the
    agent's own main filename instead, so a file-count check still sees a
    second project instruction file rather than losing it outright. A rule
    that does check the filename's value is left unrelocated in that case —
    renaming it to pass classification would substitute a different failure
    for the one the fixture exists to prove.

    Returns a scaffolded copy with the relocation applied, or None when the
    fixture carries no `.claude/rules/` file, the target agent already
    classifies that path itself (Claude, Copilot), or no safe relocation
    target exists.
    """
    rules_root = fixture_root / ".claude" / "rules"
    sources = [p for p in rules_root.rglob("*") if p.is_file()] if rules_root.is_dir() else []
    if not sources or _agent_recognizes_claude_rules(file_types):
        return None

    checks_filename = any(c.check == "filename_matches_pattern" for c in checks)
    md_rules_dir = _agent_markdown_rules_dir(file_types)
    main_filename = None if checks_filename else _agent_main_filename(file_types)
    if not md_rules_dir and not main_filename:
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_agent_rules_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)

    for source in sources:
        rel = source.relative_to(rules_root)
        source_in_tmp = tmp_dir / ".claude" / "rules" / rel
        if not source_in_tmp.is_file():
            continue
        dest = tmp_dir / md_rules_dir / rel if md_rules_dir else tmp_dir / "modular-secondary" / str(main_filename)
        dest.parent.mkdir(parents=True, exist_ok=True)
        source_in_tmp.rename(dest)

    claude_dir = tmp_dir / ".claude"
    if claude_dir.is_dir() and not any(claude_dir.rglob("*")):
        shutil.rmtree(claude_dir, ignore_errors=True)

    return tmp_dir


def _scaffold_fixture(
    fixture_root: Path,
    checks: list[Check],
    file_types: list[FileTypeDeclaration],
) -> Path | None:
    """Create a scaffolded copy of a pass fixture with M check dependencies.

    Reads mechanical checks and creates minimal structure so that
    checks like file_exists, directory_exists, glob_count, git_tracked
    can pass. Only applied to pass fixtures.

    Returns the scaffolded temp directory, or None if no scaffolding needed.
    """
    actions = _collect_scaffold_actions(checks)
    if not actions:
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_scaffold_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)

    for action_type, args in actions:
        _apply_scaffold_action(action_type, args, tmp_dir, file_types)

    return tmp_dir


def _scaffold_file_removal(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Remove forbidden file from pass scaffold (for file_absent checks)."""
    import glob as globmod

    pattern = str(args.get("pattern", ""))
    if not pattern:
        return
    # Try as plain path first
    target = tmp_dir / pattern
    if target.exists():
        target.unlink()
        return
    # Try as glob
    for match in globmod.glob(str(tmp_dir / pattern), recursive=True):
        Path(match).unlink()


# ── Fail fixture scaffolding ─────────────────────────────────────────


_SCAFFOLDABLE_FAIL_CHECKS: dict[str, str] = {
    "filename_matches_pattern": "filename_mismatch",
    "glob_count": "glob_count_deficit",
    "file_count": "glob_count_deficit",
    "file_absent": "file_present",
}


def _collect_fail_scaffold_actions(
    checks: list[Check],
) -> list[tuple[str, dict[str, Any]]]:
    """Extract scaffoldable fail actions from mechanical checks."""
    actions: list[tuple[str, dict[str, Any]]] = []
    for check in checks:
        if check.type != "mechanical":
            continue
        check_name = check.check or ""
        action_type = _SCAFFOLDABLE_FAIL_CHECKS.get(check_name)
        if action_type:
            actions.append((action_type, check.args or {}))
    return actions


def _apply_fail_scaffold_action(
    action_type: str,
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Apply a single fail scaffold action to the temp directory."""
    if action_type == "filename_mismatch":
        _scaffold_filename_mismatch(args, tmp_dir, file_types)
    elif action_type == "glob_count_deficit":
        _scaffold_glob_count_deficit(args, tmp_dir)
    elif action_type == "file_present":
        _scaffold_file_present(args, tmp_dir)


def _get_target_patterns_from_args(
    args: dict[str, Any],
    file_types: list[FileTypeDeclaration],
) -> list[str]:
    """Get file patterns from args or file_types for scaffolding."""
    path_pattern = args.get("path", "")
    if path_pattern:
        return [str(path_pattern)]
    # Fall back to first file type's patterns
    if file_types:
        return list(file_types[0].patterns)
    return []


def _scaffold_filename_mismatch(
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Rename existing files so they fail filename_matches_pattern.

    Preserves the file extension so glob patterns still find the file,
    but uses a name that won't match the regex pattern.
    """
    import glob as globmod

    for fp in _get_target_patterns_from_args(args, file_types):
        resolved = str(tmp_dir / fp)
        for match_path in globmod.glob(resolved, recursive=True):
            match = Path(match_path)
            if match.is_file():
                dest = match.parent / f"_scaffold_invalid{match.suffix}"
                match.rename(dest)
                return  # One rename is sufficient to cause failure
    # No existing files to rename — create one with a bad name
    patterns = _get_target_patterns_from_args(args, file_types)
    concrete = _glob_to_concrete(patterns[0] if patterns else "**/*.md")
    base = Path(concrete)
    target = tmp_dir / base.parent / f"_scaffold_invalid{base.suffix or '.md'}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()


def _scaffold_glob_count_deficit(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Remove files to get count below min for glob_count/file_count checks."""
    raw_pattern = str(args.get("pattern", "**/*"))
    min_count = int(args.get("min", 1))
    existing = sorted(tmp_dir.glob(raw_pattern))
    existing_files = [f for f in existing if f.is_file()]
    # Remove files until count is below min
    target_count = max(0, min_count - 1)
    to_remove = len(existing_files) - target_count
    for f in existing_files[:to_remove]:
        f.unlink()


def _scaffold_file_present(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Create the forbidden file so file_absent fails."""
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return
    # Create as plain path
    target = tmp_dir / pattern
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.touch()


def _scaffold_fail_fixture(
    fixture_root: Path,
    checks: list[Check],
    file_types: list[FileTypeDeclaration],
) -> Path | None:
    """Create a scaffolded copy of a fail fixture with M check dependencies.

    Mirrors _scaffold_fixture() for the fail side. First applies pass scaffolding
    (to ensure structural dependencies exist), then applies fail actions to break
    exactly the targeted check.

    Returns the scaffolded temp directory, or None if no scaffolding needed.
    """
    fail_actions = _collect_fail_scaffold_actions(checks)
    if not fail_actions:
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_fail_scaffold_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)

    # First, apply pass scaffolding so structural deps exist
    pass_actions = _collect_scaffold_actions(checks)
    for action_type, args in pass_actions:
        _apply_scaffold_action(action_type, args, tmp_dir, file_types)

    # Then apply fail actions to break the targeted checks
    for action_type, args in fail_actions:
        _apply_fail_scaffold_action(action_type, args, tmp_dir, file_types)

    return tmp_dir

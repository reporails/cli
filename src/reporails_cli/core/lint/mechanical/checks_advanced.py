# pylint: disable=too-many-lines
"""Advanced mechanical checks — content reading, import following, aggregation.

These checks are more complex than the simple structural checks in checks.py.
They are imported and registered in MECHANICAL_CHECKS by checks.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.lint.mechanical.checks import (
    CheckResult,
    _get_counted_files,
    _get_target_files,
    _resolve_glob_targets,
    _safe_float,
)
from reporails_cli.core.mapper.imports import FENCED_BLOCK_RE, IMPORT_REF_RE
from reporails_cli.core.platform.dto.models import ClassifiedFile


def frontmatter_present(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that at least one target file has a YAML frontmatter block."""
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    return CheckResult(passed=True, message="Frontmatter block found")
        except OSError:
            continue
    return CheckResult(passed=False, message="No frontmatter block found")


def frontmatter_valid_yaml(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all frontmatter blocks contain valid YAML mappings."""
    checked = 0
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if not content.startswith("---"):
                continue
            end = content.find("---", 3)
            if end < 0:
                continue
            checked += 1
            fm = yaml.safe_load(content[3:end])
            if not isinstance(fm, dict):
                rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
                return CheckResult(
                    passed=False,
                    message=f"Frontmatter is not a YAML mapping in {match.name}",
                    location=f"{rel}:1",
                )
        except yaml.YAMLError as e:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            return CheckResult(
                passed=False,
                message=f"Invalid YAML in {match.name}: {e}",
                location=f"{rel}:1",
            )
        except OSError:
            continue
    if checked == 0:
        return CheckResult(passed=True, message="No frontmatter to validate")
    return CheckResult(passed=True, message=f"All {checked} frontmatter block(s) valid")


_BROKEN_HEADING_RE = re.compile(r"^#{1,6}[^ #\n]", re.MULTILINE)


def valid_markdown(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for structural markdown issues in target files."""
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            m = _BROKEN_HEADING_RE.search(content)
            if m:
                line_num = content[: m.start()].count("\n") + 1
                rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
                return CheckResult(
                    passed=False,
                    message=f"Broken heading (missing space after #) in {match.name}",
                    location=f"{rel}:{line_num}",
                )
        except OSError:
            continue
    return CheckResult(passed=True, message="Markdown structure valid")


def path_resolves(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that target paths exist."""
    files = _get_target_files(args, classified_files, root)
    if files:
        return CheckResult(passed=True, message="Target paths exist")
    return CheckResult(passed=False, message="No matching paths found")


def extract_imports(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for @import references in instruction files.

    Uses the canonical `IMPORT_REF_RE` and fenced-block treatment from
    `core/mapper/imports.py` so detection matches `expand_imports` — inline
    `@code`, emails, and non-path `@tokens` are excluded.
    """
    imports_found: list[str] = []
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            stripped = FENCED_BLOCK_RE.sub("", content)
            imports_found.extend(m.group(1) for m in IMPORT_REF_RE.finditer(stripped))
        except OSError:
            continue
    if imports_found:
        return CheckResult(
            passed=True,
            message=f"Found {len(imports_found)} import(s)",
            annotations={"discovered_imports": imports_found},
        )
    # No imports is valid — nothing to validate. Pass with empty annotations
    # so check_import_targets_exist sees no work and also passes.
    return CheckResult(passed=True, message="No imports found")


# Loading modes that do NOT contribute to the always-injected ("one round")
# footprint: on_demand / discoverable surfaces load only when recalled or read.
_EXCLUDED_LOADING = frozenset({"on_demand", "discoverable"})
# Progressive-disclosure surfaces (skills, agents) inject only their
# name + description metadata at startup, not their body.
_PROGRESSIVE_LOADING = frozenset({"on_invocation"})


def _metadata_bytes(path: Path) -> int:
    """Startup footprint of a progressive surface — its name + description frontmatter only."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    if not content.startswith("---") or (end := content.find("---", 3)) < 0:
        return 0
    try:
        fm = yaml.safe_load(content[3:end])
    except yaml.YAMLError:
        return 0
    if not isinstance(fm, dict):
        return 0
    return len(f"{fm.get('name', '')}{fm.get('description', '')}".encode())


def _eager_bytes(cf: ClassifiedFile) -> int:
    """Bytes a classified surface contributes to the one-round (always-injected) footprint."""
    loading = cf.properties.get("loading")
    if loading in _EXCLUDED_LOADING:
        return 0
    try:
        if loading in _PROGRESSIVE_LOADING:
            return _metadata_bytes(cf.path)
        return cf.path.stat().st_size
    except OSError:
        return 0


def aggregate_byte_size(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check the always-injected ("one round") instruction footprint against a byte cap.

    Counts only what an agent loads every round: eager files (`loading: session_start`)
    in full; progressive-disclosure surfaces (skills, agents — `loading: on_invocation`)
    by their name + description metadata only; recalled/conditional surfaces
    (`loading: on_demand` / `discoverable`, incl. recalled memory siblings) not at all.
    The `pattern` form keeps counting full file sizes (no classified metadata).
    """
    max_bytes = _safe_float(args.get("max"), float("inf"))
    if args.get("pattern"):
        total = sum(f.stat().st_size for f in _get_counted_files(args, classified_files, root))
    else:
        total = sum(_eager_bytes(cf) for cf in classified_files if cf.path.is_file())
    if total <= max_bytes:
        return CheckResult(passed=True, message=f"Total {total}B within limit")
    return CheckResult(passed=False, message=f"Total {total}B exceeds max {max_bytes}")


def import_depth(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that @import chains do not exceed max depth."""
    max_depth_val = int(args.get("max", 5))

    def follow(filepath: Path, visited: set[Path], depth: int) -> int:
        if filepath in visited or not filepath.is_file():
            return depth
        visited.add(filepath)
        try:
            content = filepath.read_text(encoding="utf-8")
        except OSError:
            return depth
        stripped = FENCED_BLOCK_RE.sub("", content)
        refs = [m.group(1) for m in IMPORT_REF_RE.finditer(stripped)]
        max_d = depth
        for ref in refs:
            target = filepath.parent / ref
            if target.is_file():
                max_d = max(max_d, follow(target, visited, depth + 1))
        return max_d

    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        deepest = follow(match, set(), 0)
        if deepest > max_depth_val:
            return CheckResult(
                passed=False,
                message=f"{match.name}: depth {deepest} exceeds max {max_depth_val}",
            )
    return CheckResult(passed=True, message=f"Import depth within limit ({max_depth_val})")


def directory_file_types(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all files in a directory match allowed extensions."""
    path = str(args.get("path", ""))
    extensions: list[str] = list(args.get("extensions", []))
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=True, message=f"Directory not found: {path} (OK)")
    bad = [f.name for f in target.iterdir() if f.is_file() and f.suffix not in extensions]
    if bad:
        return CheckResult(passed=False, message=f"Non-{extensions} files: {', '.join(bad[:5])}")
    return CheckResult(passed=True, message=f"All files in {path} match {extensions}")


def skill_entrypoint_present(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Flag skill directories that lack a SKILL.md entry point.

    Skills-root directories are located by globbing for existing entry
    files (agent-agnostic); every immediate subdirectory of a skills root
    must then contain the entry file. Project-aggregate: enumerates whole
    skills roots, so its check entry is flagged `project_scope: true` to skip under scoped runs.
    """
    entry = str(args.get("entry", "SKILL.md"))
    roots = {f.parent.parent for f in _resolve_glob_targets(f"**/{entry}", root) if f.is_file()}
    missing: list[str] = []
    for skills_root in sorted(roots):
        if not skills_root.is_dir():
            continue
        for sub in sorted(p for p in skills_root.iterdir() if p.is_dir() and not p.name.startswith(".")):
            if not (sub / entry).is_file():
                rel = sub.relative_to(root).as_posix() if sub.is_relative_to(root) else sub.name
                missing.append(rel)
    if not missing:
        return CheckResult(passed=True, message=f"All skill directories contain {entry}")
    return CheckResult(
        passed=False,
        message=f"Skill directory missing {entry}: {', '.join(missing[:5])}",
        location=f"{missing[0]}:0",
    )


def frontmatter_valid_glob(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that YAML frontmatter path entries use valid glob syntax.

    When require_matches is true, also checks that each glob pattern
    matches at least one file in the project root.
    """
    path = str(args.get("path", ""))
    require_matches = args.get("require_matches", False)
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=True, message=f"Directory not found: {path} (OK)")
    unresolved: list[str] = []
    for f in target.iterdir():
        if not f.is_file() or f.suffix != ".md":
            continue
        result = _validate_file_globs(f, root, require_matches, unresolved)
        if result is not None:
            return result
    if unresolved:
        return CheckResult(passed=False, message=f"Path globs match no files: {', '.join(unresolved)}")
    return CheckResult(passed=True, message="All frontmatter path entries valid")


def _validate_file_globs(
    f: Path,
    root: Path,
    require_matches: bool,
    unresolved: list[str],
) -> CheckResult | None:
    """Validate glob entries in a single file's frontmatter. Returns CheckResult on error, None to continue."""
    try:
        content = f.read_text(encoding="utf-8")
        if not content.startswith("---"):
            return None
        end = content.find("---", 3)
        if end < 0:
            return None
        fm = yaml.safe_load(content[3:end])
        if not isinstance(fm, dict):
            return None
        paths = fm.get("globs") or fm.get("paths") or fm.get("applyTo") or []
        if isinstance(paths, str):
            paths = [s.strip() for s in paths.split(",") if s.strip()]
        for p in paths:
            if not isinstance(p, str):
                return CheckResult(passed=False, message=f"{f.name}: non-string path: {p}")
            if p.count("[") != p.count("]"):
                return CheckResult(passed=False, message=f"{f.name}: unbalanced brackets: {p}")
            if require_matches:
                try:
                    if not any(True for _ in root.glob(p)):
                        unresolved.append(f"{f.name}: {p}")
                except ValueError as exc:
                    return CheckResult(passed=False, message=f"{f.name}: invalid glob '{p}': {exc}")
    except (OSError, yaml.YAMLError):
        pass
    return None


def count_at_most(
    _root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a metadata list has at most N entries.

    Reads a named metadata key from args (injected by pipeline from annotations).
    Args: threshold (int, default 0), plus the metadata key name -> list.
    """
    threshold = int(args.get("threshold", 0))
    items: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            items = value
            break
    if len(items) <= threshold:
        return CheckResult(passed=True, message=f"Count {len(items)} within limit ({threshold})")
    return CheckResult(passed=False, message=f"Count {len(items)} exceeds max {threshold}")


def count_at_least(
    _root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a metadata list has at least N entries.

    Reads a named metadata key from args (injected by pipeline from annotations).
    Args: threshold (int, default 1), plus the metadata key name -> list.
    """
    threshold = int(args.get("threshold", 1))
    items: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            items = value
            break
    if len(items) >= threshold:
        return CheckResult(passed=True, message=f"Count {len(items)} meets minimum ({threshold})")
    return CheckResult(passed=False, message=f"Count {len(items)} below minimum {threshold}")


def check_import_targets_exist(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all @import paths from metadata resolve to existing files.

    Reads import paths from args (injected by pipeline from D check annotations).
    Each path is resolved relative to the target instruction file's directory.
    """
    import_paths: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            import_paths = value
            break
    if not import_paths:
        return CheckResult(passed=True, message="No import paths to check")
    missing: list[str] = []
    for ref in import_paths:
        clean = ref.lstrip("@")
        if not (root / clean).exists():
            missing.append(clean)
    if missing:
        return CheckResult(
            passed=False,
            message=f"Unresolved imports: {', '.join(missing[:5])}",
        )
    return CheckResult(passed=True, message=f"All {len(import_paths)} import(s) resolve")


# Markdown link extraction — mirrors `link_walker._INLINE_LINK_RE` /
# `_REF_DEFINITION_RE` so the broken-target rule and the generic-class
# classifier agree on what counts as a Markdown link.
_INLINE_LINK_RE = re.compile(r"\[(?:[^\]]+)\]\(([^)]+)\)")
_REF_DEFINITION_RE = re.compile(r"^\s*\[(?:[^\]]+)\]:\s*(\S+)", re.MULTILINE)
# Code-span stripping — `[text](path)` inside backticks is documentation,
# not a real link. Mirror this with `link_walker._strip_code_spans`.
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _strip_code_spans(text: str) -> str:
    """Remove fenced code blocks and inline code spans before link extraction."""
    text = _CODE_FENCE_RE.sub("", text)
    return _INLINE_CODE_RE.sub("", text)


def _is_external_link(target: str) -> bool:
    """Skip URLs (http://, mailto:, etc.) and pure anchor refs."""
    if "://" in target or target.startswith("mailto:"):
        return True
    return target.startswith("#")


def _strip_anchor(target: str) -> str:
    if "#" in target:
        target = target.split("#", 1)[0]
    return target.strip()


def extract_markdown_links(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Discover `[text](path)` + `[ref]: path` link targets in target files.

    Annotates `discovered_markdown_links` as a list of `"<file-rel>::<target>"`
    entries; the validate step splits on `::` to resolve each target against
    the source file's parent directory.

    Filters URLs (`://`, `mailto:`), bare anchor refs (`#frag`), and absolute
    paths (`/foo`). Anchors trailing on otherwise-valid links are stripped.
    Mirrors the regex constants in `core/classify/link_walker.py` so the
    broken-target rule and the generic-class classifier disagree on no link.
    """
    annotations: list[str] = []
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            text = match.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = _strip_code_spans(text)
        rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else str(match)
        targets: list[str] = []
        targets.extend(m.group(1).strip() for m in _INLINE_LINK_RE.finditer(text))
        targets.extend(m.group(1).strip() for m in _REF_DEFINITION_RE.finditer(text))
        for raw in targets:
            cleaned = _strip_anchor(raw)
            if not cleaned or _is_external_link(cleaned):
                continue
            # Absolute paths (`/foo/bar.md`) are user-system paths, not
            # project-relative; treat as out-of-scope.
            if cleaned.startswith("/"):
                continue
            annotations.append(f"{rel}::{cleaned}")
    if annotations:
        return CheckResult(
            passed=True,
            message=f"Found {len(annotations)} markdown link(s)",
            annotations={"discovered_markdown_links": annotations},
        )
    return CheckResult(passed=True, message="No markdown links found")


def check_markdown_link_targets_exist(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Verify each discovered markdown link resolves to an existing path.

    Reads `discovered_markdown_links` from args (D-check annotations,
    `"<file-rel>::<target>"` entries). Each target is resolved relative to
    the source file's parent directory. Returns missing targets; passes
    when all resolve.
    """
    entries: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            entries = value
            break
    if not entries:
        return CheckResult(passed=True, message="No markdown links to check")
    missing: list[str] = []
    for raw in entries:
        if "::" not in raw:
            continue
        src_rel, target = raw.split("::", 1)
        src_path = root / src_rel
        base_dir = src_path.parent if src_path.exists() else root
        candidate = (base_dir / target).resolve()
        if not candidate.exists():
            missing.append(f"{src_rel} -> {target}")
    if missing:
        return CheckResult(
            passed=False,
            message=f"Broken markdown link(s): {'; '.join(missing[:5])}",
        )
    return CheckResult(passed=True, message=f"All {len(entries)} markdown link(s) resolve")


def filename_matches_pattern(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that target filenames match a regex pattern.

    Args: pattern (regex string), path (optional glob for file targets).
    """
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="filename_matches_pattern: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"filename_matches_pattern: invalid regex: {e}")
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        if not compiled.search(match.name):
            return CheckResult(
                passed=False,
                message=f"{match.name}: does not match pattern {pattern}",
            )
    return CheckResult(passed=True, message="All filenames match pattern")


def _scope_dir_from_glob(glob_pattern: str) -> str:
    """Extract the non-glob directory prefix from a glob pattern.

    >>> _scope_dir_from_glob(".claude/skills/**/*.md")
    '.claude/skills'
    >>> _scope_dir_from_glob("**/CLAUDE.md")
    ''
    """
    parts = glob_pattern.replace("\\", "/").split("/")
    dirs: list[str] = []
    for part in parts:
        if any(c in part for c in "*?[{"):
            break
        dirs.append(part)
    return "/".join(dirs)


def _resolve_scope_dir(match_type: str, classified_files: list[ClassifiedFile]) -> str:
    """Resolve a scope directory from classified files matching the given type."""
    if not match_type:
        return ""
    for cf in classified_files:
        if cf.file_type == match_type:
            rel = str(cf.path.parent)
            # Extract the non-glob prefix from the relative path
            return _scope_dir_from_glob(rel)
    return ""


def file_absent(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that NO file matching the pattern exists.

    When ``_match_type`` is injected (from rule.match.type), scopes the search
    to the target directory instead of the project root.
    """
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="file_absent: no pattern specified")
    match_type = str(args.get("_match_type", ""))
    scope_dir = _resolve_scope_dir(match_type, classified_files)

    # If the rule targets a specific file type but no files of that type were
    # classified, the scope cannot be resolved.  Falling through to the project
    # root would produce false positives (e.g. root README.md flagged by a
    # skill-scoped rule), so return pass.
    if match_type and not scope_dir:
        return CheckResult(passed=True, message=f"No {match_type} files classified")

    if scope_dir:
        search_pattern = f"{scope_dir}/**/{pattern}"
        direct_path = root / scope_dir / pattern
    else:
        search_pattern = pattern
        direct_path = root / pattern

    matches = _resolve_glob_targets(search_pattern, root)
    if matches:
        name = matches[0].relative_to(root).as_posix() if matches[0].is_relative_to(root) else matches[0].name
        return CheckResult(passed=False, message=f"Forbidden file exists: {name}")
    if direct_path.exists():
        rel = f"{scope_dir}/{pattern}" if scope_dir else pattern
        return CheckResult(passed=False, message=f"Forbidden file exists: {rel}")
    return CheckResult(passed=True, message="Forbidden file not found")


def content_absent(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a regex pattern does NOT appear in matching files."""
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="content_absent: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"content_absent: invalid regex: {e}")
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if compiled.search(content):
                return CheckResult(
                    passed=False,
                    message=f"{match.name}: forbidden pattern found",
                )
        except OSError:
            continue
    return CheckResult(passed=True, message="Forbidden pattern not found")


def frontmatter_extra_keys(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that frontmatter contains only allowed keys.

    Args (via args dict):
        allowed: list of allowed key names (e.g., ["paths"])
    """
    allowed = set(args.get("allowed", []))
    if not allowed:
        return CheckResult(passed=False, message="frontmatter_extra_keys: no allowed keys specified")
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if not content.startswith("---"):
                continue
            end = content.find("---", 3)
            if end < 0:
                continue
            fm = yaml.safe_load(content[3:end])
            if not isinstance(fm, dict):
                continue
            extra = sorted(k for k in fm if k not in allowed)
            if extra:
                rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
                keys_str = ", ".join(extra)
                allowed_str = ", ".join(sorted(allowed))
                msg = f"Unrecognized frontmatter keys: {keys_str} — only {allowed_str} is processed"
                return CheckResult(passed=False, message=msg, location=f"{rel}:1")
        except (OSError, ValueError):
            continue
    return CheckResult(passed=True, message="No extra frontmatter keys")

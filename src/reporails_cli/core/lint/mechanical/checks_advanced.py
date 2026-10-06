"""Advanced mechanical checks — content reading, import following, aggregation.

These checks are more complex than the simple structural checks in checks.py.
They are imported and registered in MECHANICAL_CHECKS by checks.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.agents import load_project_exclude_dirs
from reporails_cli.core.discovery.walk import safe_resolve, walk_files, walk_glob_matches
from reporails_cli.core.lint.mechanical.checks import (
    _get_counted_files,
    _resolve_glob_targets,
    _safe_float,
    get_target_files,
)
from reporails_cli.core.mapper.imports import import_refs
from reporails_cli.core.mapper.inspect import path_filter_key, split_top_level_commas
from reporails_cli.core.mapper.parse import parse_blocks
from reporails_cli.core.mapper.skills import one_level_skills_roots, slot_subfolders
from reporails_cli.core.mapper.structure import link_targets, strip_anchor
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.utils.utils import (
    FrontmatterBlock,
    read_frontmatter,
    read_frontmatter_file,
)


def frontmatter_present(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that every target file has a YAML frontmatter block.

    Each file with no frontmatter block is its own occurrence, so one
    compliant sibling in a multi-file match set does not hide another
    file's missing block.
    """
    targets = [m for m in get_target_files(args, classified_files, root) if m.is_file()]
    if not targets:
        return CheckResult(passed=False, message="No frontmatter block found")

    missing: list[tuple[str, str]] = []
    for match in targets:
        read = read_frontmatter_file(match, lenient=bool(args.get("lenient", False)))
        if read is None or read.block is None:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            missing.append((f"{rel}:0", "No frontmatter block found"))

    if missing:
        return CheckResult(
            passed=False,
            message=f"{len(missing)} file(s) missing a frontmatter block",
            occurrences=missing,
        )
    return CheckResult(passed=True, message="Frontmatter block found in all target file(s)")


def frontmatter_matches_dirname(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check a frontmatter field equals its file's containing directory name.

    Generic over the field (`args['field']`, default `name`) and the target
    file set, so any rule asserting "frontmatter <field> == directory" reuses
    it. Two inputs per file: the field value read through the YAML parser (so a
    quoted scalar such as `"foo-bar"` compares as the bare string `foo-bar`)
    and the parent directory name. A present value that differs from the
    directory is the violation — a bare presence-regex cannot express it. An
    absent value is not a violation: a loader that defaults the field to the
    directory name trivially matches.

    Operates on the classified target files so an external single-file target
    resolves correctly, unlike a project-root glob.
    """
    field = str(args.get("field", "name"))
    for target in get_target_files(args, classified_files, root):
        if not target.is_file():
            continue
        directory = target.parent.name
        read = read_frontmatter_file(target, lenient=bool(args.get("lenient", False)))
        fm = read.data if read is not None else None
        if fm is None or not isinstance(fm.get(field), str):
            continue
        value = fm[field].strip()
        if value != directory:
            rel = target.relative_to(root).as_posix() if target.is_relative_to(root) else target.name
            return CheckResult(
                passed=False,
                message=f"Frontmatter {field} '{value}' does not match directory '{directory}'",
                location=f"{rel}:1",
            )
    return CheckResult(passed=True, message=f"Frontmatter {field} matches directory")


def frontmatter_valid_yaml(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that every target file's frontmatter block reads as a YAML mapping.

    Each file whose block does not is its own occurrence, at the line of the problem; a file
    with no block passes (a missing block is the presence check's finding). With `args.lenient`
    a block that reads once its one-line values are quoted passes, as a path filter is read.
    """
    broken: list[tuple[str, str]] = []
    for match in get_target_files(args, classified_files, root):
        read = read_frontmatter_file(match, lenient=bool(args.get("lenient", False))) if match.is_file() else None
        if read is not None and read.problem is not None:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            broken.append((f"{rel}:{read.problem.line}", f"Frontmatter is not valid YAML: {read.problem.message}"))
    if broken:
        return CheckResult(
            passed=False,
            message=f"{len(broken)} file(s) with frontmatter that is not valid YAML",
            occurrences=broken,
        )
    return CheckResult(passed=True, message="All frontmatter blocks read as YAML")


# A paragraph line that opens with hashes and no space after them: the heading it was meant to be,
# which the parse reads as running text.
_BROKEN_HEADING_RE = re.compile(r"#{1,6}[^ #]")


def _broken_heading_line(content: str) -> int | None:
    """File line of the first paragraph line that looks like a heading missing its space after `#`.

    Only running text is read: a `#!/bin/bash` or `# comment` line in a fenced block, an indented
    code block or the frontmatter is not a heading and is not looked at.
    """
    tokens, offset = parse_blocks(content)
    for i, tok in enumerate(tokens):
        if tok.type != "inline" or tokens[i - 1].type != "paragraph_open" or tokens[i - 1].level:
            continue
        for n, line in enumerate(tok.content.split("\n")):
            if _BROKEN_HEADING_RE.match(line):
                return int(tok.map[0]) + offset + n + 1
    return None


def valid_markdown(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for structural markdown issues in target files."""
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8", errors="replace")
            line_num = _broken_heading_line(content)
            if line_num is not None:
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
    files = get_target_files(args, classified_files, root)
    if files:
        return CheckResult(passed=True, message="Target paths exist")
    return CheckResult(passed=False, message="No matching paths found")


def extract_imports(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for @import references in instruction files.

    Reads the imports through `import_refs` in `core/mapper/imports.py` so detection
    matches `expand_imports` — a reference inside code (a fenced or indented block, or
    a span such as `` `npx @reporails/cli check .` ``, documenting a scoped npm
    package), an email and a non-path `@token` are not imports.
    """
    imports_found: list[str] = []
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            imports_found.extend(import_refs(match.read_text(encoding="utf-8", errors="replace")))
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
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    fm = read_frontmatter(content).data
    if fm is None:
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
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return depth
        max_d = depth
        for ref in import_refs(content):
            target = filepath.parent / ref
            if target.is_file():
                max_d = max(max_d, follow(target, visited, depth + 1))
        return max_d

    for match in get_target_files(args, classified_files, root):
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
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Flag skill directories that lack a SKILL.md entry point.

    Skills roots come from the run's skill entry patterns (the folders that hold the
    recorded skills), never from where a `SKILL.md` happens to sit; every immediate
    subdirectory of such a root must contain the entry file. A root whose pattern lets a
    skill sit deeper (a category folder) is not checked. Project-aggregate: enumerates whole
    skills roots, so its check entry is marked `project_scope: aggregate` to skip under scoped runs.
    """
    entry = str(args.get("entry", "SKILL.md"))
    roots = one_level_skills_roots(classified_files, root)
    missing: list[str] = []
    for skills_root in sorted(roots):
        for sub in slot_subfolders(skills_root):
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
    matches at least one file in the project root. Walks the target
    directory recursively so nested rule files (e.g. a subfolder under
    `.cursor/rules/`) are covered, and accepts `.mdc` alongside `.md` —
    Cursor's own path-scoped rule extension.
    """
    path = str(args.get("path", ""))
    require_matches = args.get("require_matches", False)
    lenient = bool(args.get("lenient", False))
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=True, message=f"Directory not found: {path} (OK)")
    unresolved: list[tuple[str, str]] = []
    exclude_dirs = load_project_exclude_dirs(root)
    rule_files = walk_files(target, exclude_dirs, lambda f: f.suffix in (".md", ".mdc"))
    for f in sorted(rule_files):
        result = _validate_file_globs(f, root, require_matches, lenient, unresolved, exclude_dirs)
        if result is not None:
            return result
    if unresolved:
        return CheckResult(
            passed=False,
            message=f"Path globs match no files: {', '.join(glob for _, glob in unresolved)}",
            occurrences=[(loc, f"Path glob `{glob}` matches no file in the project") for loc, glob in unresolved],
        )
    return CheckResult(passed=True, message="All frontmatter path entries valid")


# The path-filter keys read from a file no file type claims.
_PATH_KEYS = ("globs", "paths", "applyTo")


def _validate_file_globs(
    f: Path,
    root: Path,
    require_matches: bool,
    lenient: bool,
    unresolved: list[tuple[str, str]],
    exclude_dirs: frozenset[str],
) -> CheckResult | None:
    """Validate glob entries in a single file's frontmatter. Returns CheckResult on error, None to continue.

    Each glob that matches no project file is added to ``unresolved`` as ``(file:line, glob)``, on the
    line that holds it. Globs match from the project root (a leading ``/`` is dropped); only the folder
    a glob names is walked, and the walk stops at the first match.
    """
    read = read_frontmatter_file(f, lenient=lenient)
    if read is None or read.block is None or read.data is None:
        return None
    key = path_filter_key(f, root)
    paths = (read.data.get(key) if key else next((read.data[k] for k in _PATH_KEYS if read.data.get(k)), None)) or []
    if isinstance(paths, str):
        paths = split_top_level_commas(paths)
    for p in paths:
        if not isinstance(p, str):
            return CheckResult(passed=False, message=f"{f.name}: non-string path: {p}")
        if p.count("[") != p.count("]"):
            return CheckResult(passed=False, message=f"{f.name}: unbalanced brackets: {p}")
        if require_matches and next(walk_glob_matches(root, p, exclude_dirs), None) is None:
            unresolved.append((f"{f.relative_to(root).as_posix()}:{_frontmatter_line(read.block, p)}", p))
    return None


def _frontmatter_line(block: FrontmatterBlock, value: str) -> int:
    """The 1-based line of the frontmatter entry holding ``value``: the list item that is ``value``, else the line
    that quotes it, else any line naming it; 0 (the file) when none does."""
    lines = block.text.split("\n")
    tests = (
        lambda line: line.strip().removeprefix("-").strip().strip("\"'") == value,
        lambda line: f'"{value}"' in line or f"'{value}'" in line,
        lambda line: value in line,
    )
    for test in tests:
        for n, line in enumerate(lines, start=block.first_line):
            if test(line):
                return n
    return 0


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


def _is_external_link(target: str) -> bool:
    """Skip URLs (http://, mailto:, etc.) and pure anchor refs."""
    if "://" in target or target.startswith("mailto:"):
        return True
    return target.startswith("#")


def broken_link_message(target: str) -> str:
    """The finding text for a link whose target does not exist."""
    return f"Broken link — `{target}` does not exist."


def extract_markdown_links(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Discover `[text](path)` + `[ref]: path` link targets in target files.

    Annotates `discovered_markdown_links` as a list of `"<file-rel>::<target>::<line>"`
    entries; the validate step splits on `::` to resolve each target against
    the source file's parent directory and to report it on its own line.

    Filters URLs (`://`, `mailto:`), bare anchor refs (`#frag`), and absolute
    paths (`/foo`). Anchors trailing on otherwise-valid links are stripped.
    Reads links from the markdown parse (`link_targets`), the same reading the
    generic-class classifier uses, so the two disagree on no link.
    """
    annotations: list[str] = []
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            text = match.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else str(match)
        for line, raw in link_targets(text):
            cleaned = strip_anchor(raw)
            if not cleaned or _is_external_link(cleaned):
                continue
            # Absolute paths (`/foo/bar.md`) are user-system paths, not
            # project-relative; treat as out-of-scope.
            if cleaned.startswith("/"):
                continue
            annotations.append(f"{rel}::{cleaned}::{line}")
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
    `"<file-rel>::<target>::<line>"` entries). Each target is resolved relative
    to the source file's parent directory. Each missing target is one occurrence
    located on its own line; passes when all resolve.
    """
    entries: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            entries = value
            break
    if not entries:
        return CheckResult(passed=True, message="No markdown links to check")
    missing: list[tuple[str, str]] = []
    for raw in entries:
        parts = raw.split("::")
        if len(parts) != 3:
            continue
        src_rel, target, line = parts
        src_path = root / src_rel
        base_dir = src_path.parent if src_path.exists() else root
        candidate = safe_resolve(base_dir / target)
        if not candidate.exists():
            missing.append((f"{src_rel}:{line}", broken_link_message(target)))
    if missing:
        return CheckResult(
            passed=False,
            message=f"{len(missing)} broken markdown link(s)",
            occurrences=missing,
        )
    return CheckResult(passed=True, message=f"All {len(entries)} markdown link(s) resolve")


def filename_matches_pattern(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that every target filename matches a regex pattern.

    Args: pattern (regex string), path (optional glob for file targets).
    Each non-matching file is its own occurrence, so a correctly-named
    sibling does not hide another file's bad name.
    """
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="filename_matches_pattern: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"filename_matches_pattern: invalid regex: {e}")
    bad: list[tuple[str, str]] = []
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        if not compiled.search(match.name):
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            bad.append((f"{rel}:0", f"{match.name}: does not match pattern {pattern}"))
    if bad:
        return CheckResult(
            passed=False,
            message=f"{len(bad)} filename(s) do not match pattern {pattern}",
            occurrences=bad,
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


def _match_type_label(match_type: str | list[str]) -> str:
    """Render `_match_type` for a human-facing message — `config/hooks`, never a list repr."""
    return "/".join(match_type) if isinstance(match_type, list) else str(match_type)


def _resolve_scope_dir(match_type: str | list[str], classified_files: list[ClassifiedFile]) -> str:
    """Resolve a scope directory from classified files matching the given type.

    `match_type` may be a list (`match: {type: [config, hooks]}`). The listed types
    are tried in SORTED order (not classified-files discovery order), each checked
    against every classified file, so the resolved directory is deterministic — it
    always anchors on the alphabetically-first type that has a classified file,
    regardless of filesystem walk order.
    """
    from reporails_cli.core.platform.policy.matching import _prop_matches

    if not match_type:
        return ""
    types = sorted(match_type) if isinstance(match_type, list) else [match_type]
    for one_type in types:
        for cf in classified_files:
            if _prop_matches(one_type, cf.file_type):
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
    match_type = args.get("_match_type", "")
    scope_dir = _resolve_scope_dir(match_type, classified_files)

    # If the rule targets a specific file type but no files of that type were
    # classified, the scope cannot be resolved.  Falling through to the project
    # root would produce false positives (e.g. root README.md flagged by a
    # skill-scoped rule), so return pass.
    if match_type and not scope_dir:
        return CheckResult(passed=True, message=f"No {_match_type_label(match_type)} files classified")

    if scope_dir:
        scope_root = root / scope_dir
        direct_path = scope_root / pattern
        matches = list(walk_glob_matches(scope_root, f"**/{pattern}", load_project_exclude_dirs(root)))
    else:
        direct_path = root / pattern
        matches = _resolve_glob_targets(pattern, root)
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
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8", errors="replace")
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
    for match in get_target_files(args, classified_files, root):
        read = read_frontmatter_file(match, lenient=bool(args.get("lenient", False))) if match.is_file() else None
        if read is None or read.data is None:
            continue
        extra = sorted(k for k in read.data if k not in allowed)
        if extra:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            keys_str = ", ".join(extra)
            allowed_str = ", ".join(sorted(allowed))
            msg = f"Unrecognized frontmatter keys: {keys_str} — only {allowed_str} is processed"
            return CheckResult(passed=False, message=msg, location=f"{rel}:1")
    return CheckResult(passed=True, message="No extra frontmatter keys")

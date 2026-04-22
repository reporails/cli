---
name: add-changelog-entry
description: Add a changelog entry to UNRELEASED.md
---

# /add-changelog-entry

Append a changelog entry to `UNRELEASED.md` based on the current `git diff` or recent file modifications.

## Step 1 — Detect changes via `git diff`

Run `git diff --cached --name-only` or `git diff --name-only` to list every modified file path under `src/` and `tests/`. The file paths from `git diff` determine both the `[Area]` tag and the `### [Category]` heading for the changelog entry.

## Step 2 — Resolve the area tag from file path

Map each changed file path to its `[Area]` tag using the prefix table:

- `src/reporails_cli/interfaces/cli/` → `[CLI]`
- `src/reporails_cli/core/` → `[CORE]`
- `src/reporails_cli/bundled/` → `[BUNDLED]`
- `src/reporails_cli/formatters/` → `[FORMATTERS]`
- `README.md`, `docs/` → `[DOCS]`
- `CLAUDE.md`, `.ails/backbone.yml`, `.claude/` → `[META]`

When changes span multiple areas, pick the area containing the primary behavioral change. Ancillary files like `tests/` inherit the area of the `src/` module they exercise.

## Step 3 — Classify the category

Select the `### [Category]` heading from the Keep a Changelog set based on what the diff shows:

- `### Added` — new files, new functions, new `class` definitions not present before
- `### Changed` — modified signatures, altered behavior in existing `src/` modules
- `### Deprecated` — functions or flags marked for future removal
- `### Removed` — deleted files, removed exports, dropped CLI flags
- `### Fixed` — bug corrections where previous behavior was incorrect
- `### Security` — vulnerability patches, dependency bumps for CVEs

The category reflects user-visible impact. Internal refactors that preserve behavior use `### Changed` with a note about the refactor scope.

## Step 4 — Append to `UNRELEASED.md`

Compose a 3-7 word description naming the specific construct affected (function name, module path, or CLI flag). Append the entry to `UNRELEASED.md` under the matching `### [Category]` heading — create the heading if it does not exist yet. Format each entry as:

```markdown
### Added
- [CORE]: `validate_rule()` support for `content_query` checks
```

Append the `UNRELEASED.md` entry without asking for confirmation. Prompting for approval on changelog entries adds friction without catching errors that `git diff` review would miss.

Target `UNRELEASED.md` exclusively when appending entries via this skill. `CHANGELOG.md` is read-only during development — the release workflow at `scripts/pre-release-check.sh` migrates entries at version-tag time.
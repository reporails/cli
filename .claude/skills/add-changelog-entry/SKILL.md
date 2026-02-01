---
name: add-changelog-entry
description: Add a changelog entry to UNRELEASED.md
---

# /add-changelog-entry

Automatically add a changelog entry to PROJECT_ROOT/UNRELEASED.md.

## Instructions

1. Check git diff or recent file modifications
2. Determine the area from the file path:
   - interfaces/cli/ → [CLI]
   - core/ → [CORE]
   - bundled/ → [BUNDLED]
   - formatters/ → [FORMATTERS]
   - README.md → [DOCS]
   - CLAUDE.md, backbone.yml, .claude/, .reporails/ → [META]
3. Determine the category:
   - New files/content → Added
   - Modified existing → Changed
   - Marked as deprecated/obsolete → Deprecated
   - Removed content → Removed
   - Bug fixes → Fixed
   - Security-related changes → Security
4. Write a concise description (3-7 words)
5. Append to UNRELEASED.md under the correct category section
6. Create the category section if it doesn't exist

## Format

```markdown
### [Category]
- [Area]: [Description]
```

## Categories

Added, Changed, Deprecated, Removed, Fixed, Security

## Areas

- [CLI] – CLI interface (interfaces/cli/)
- [CORE] – Core domain logic
- [BUNDLED] – Bundled config (levels.yml, capability-patterns.yml)
- [FORMATTERS] – Output formatters
- [DOCS] – README, general documentation
- [META] – CLAUDE.md, backbone.yml, repo structure

## Example

```markdown
### Added
- [CORE]: Semantic rule caching support

### Changed
- [FORMATTERS]: Updated compact output format
```

Do not ask for confirmation. Just do it.

# Changelog

How to maintain the changelog and create releases.

## Format

[Keep a Changelog](https://keepachangelog.com/) with project-specific conventions.

## Files

| File | Purpose |
|------|---------|
| `UNRELEASED.md` | Accumulates changes during development |
| `CHANGELOG.md` | Released versions (moved from UNRELEASED) |

## Adding Entries

Add to `UNRELEASED.md` as you work:

```markdown
### Added
- [AREA]: Brief description of what was added

### Changed
- [AREA]: Brief description of what changed

### Fixed
- [AREA]: Brief description of what was fixed

### Removed
- [AREA]: Brief description of what was removed
```

**Areas:** CLI, CORE, BUNDLED, FORMATTERS, DOCS, META

## Writing Good Entries

**Do:**
- Group by theme, not by file
- Lead with what matters to users
- Be specific but concise

**Don't:**
- List every file changed
- Use commit-message style entries
- Bury important changes in lists

**Good:**
```markdown
- [CORE]: Semantic rule caching support
- [CLI]: Added --quiet-semantic flag to suppress messages
```

**Bad:**
```markdown
- Added cache.py
- Changed main.py to add flag
```

## Creating a Release

**Process:**
1. Review `UNRELEASED.md`
2. Group similar changes by theme
3. Write release summary for `CHANGELOG.md`
4. Clear `UNRELEASED.md` (keep header)
5. Commit, tag, push

**Release entry template:**

```markdown
## [X.Y.Z] - YYYY-MM-DD

One-line summary of the release.

### Added
- **Theme**: Summary

### Changed
- **Theme**: Summary

### Fixed
- **Theme**: Summary
```

## Tagging

```bash
git tag X.Y.Z
git push origin X.Y.Z
```

Tag format: [SemVer](https://semver.org/) (e.g., `0.2.0`)

## Version Numbering

| Change Type | Bump | Example |
|-------------|------|---------|
| Breaking changes | Major | 1.0.0 → 2.0.0 |
| New features (backwards compatible) | Minor | 0.1.0 → 0.2.0 |
| Bug fixes | Patch | 0.1.0 → 0.1.1 |

Pre-1.0: Minor bumps for features, patch for fixes. Breaking changes OK.

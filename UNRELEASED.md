# Unreleased

### Added

### Changed

### Fixed

- Check: when your project is a git repository, a separate repository inside it, such as a repository you cloned into the project or a git worktree under `.claude/worktrees/`, is no longer checked as part of your project, so its rules, skills and agents no longer add to your findings and score. Check it on its own with `ails check <folder>`. Git submodules, and skills or agents you cloned into your own `.claude/skills/` or `.claude/agents/` folder, are still checked.
- Check: an `@` import that does not resolve is reported on the file that holds it, at the import's line, instead of on your main instruction file, and a relative import is looked up from the folder of the file that holds it. Before, a correct relative import in a nested `CLAUDE.md` could be reported as broken.

### Removed

### Internal

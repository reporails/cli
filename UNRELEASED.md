# Unreleased

### Added

### Changed

### Fixed

- On Windows, `ails check` names a file relative to its project, finds the files of a `~/.claude` folder and keeps a linked rule inside its project when the folder is spelled with a short (8.3) name; a file in the folder the command runs in is named with `/`, not its full path.
- With a home folder reached through a link, `ails check` on a `~/.claude` folder reports that folder's findings instead of none.

### Removed

### Internal

- The Windows check scenarios and the MCP x-ray two-call scenario lose their skip tag. The two-call scenario reads the page while the agent's MCP server still runs, because on Windows the test client ends the server's process tree, the page with it.
- Three check scenarios guard linked folders: a `.claude/rules` folder linked to a dotfiles folder stays part of `ails check .claude`, a linked file under a `~/.claude` linked to a dotfiles folder keeps its user-level root, and a `~/.claude` folder keeps its findings when the home folder is reached through a link.

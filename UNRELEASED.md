# Unreleased

### Added

### Changed

- `ails config set` accepts every setting that holds a name, a list of names or true/false: `default_agent`, `disabled_rules`, `exclude_dirs`, `exclude_files`, `generic_scanning`, `heal_exclude` and `packages`. With `--global` it accepts the same settings except `heal_exclude`, which only the project files carry.
- `<!-- ails-disable-line format -->` and `<!-- ails-disable-line bold -->` no longer silence anything: name the rule, `CORE:E:0003`, or its slug, as for every other rule.

### Fixed

- `disabled_rules` turns a rule off for every check that reports it. A rule listed there no longer shows up from the checks on each instruction (such as `CORE:E:0003` for a code name without backticks or bold on an instruction) or from what the server sends (its findings, the per-file counts on a free plan and the cross-file repetitions and overlaps), and a rule your agent's rule set leaves out is not reported either. `ails-disable-line` still silences a single line.
- A config file that cannot be read stops `ails check` with an error naming the file, the line and the problem, and exit code 2, instead of running on defaults without saying so. This covers `.ails/config.yml`, `.ails/config.local.yml` and `~/.reporails/config.yml`. `ails config get`, `set` and `list` read the file the same way `ails check` does, so both give the same answer for the same file, and `ails config set` no longer overwrites a file it cannot read. MCP `validate` returns the error as `config_unreadable` with the same message, and `heal_apply` replies with that message.

### Removed

- `ails test --score`: it reported 0.0 for every rule.

- The `reporails_cli` package no longer exports `__version__` (`ails version` and `importlib.metadata.version("reporails-cli")` report it), `ValidationResult`, `JudgmentRequest` or `JudgmentResponse`, and `formatters.json.format_result` / `format_score` and `formatters.github.format_result` / `format_annotations` are gone; no command produced or called them.

### Internal

- The source passes pylint with no findings, and the pylint gate now fails on any new one.
- Code that no command reached is removed.
- `ails check` no longer reads `.ails/backbone.yml` or scans the root instruction file for values no check uses.
- Tests: two exclusion tests compare paths the same way on Windows.
- Tests: the marker check counts a module-level marker list, as pytest does, so each test carries exactly one lane.

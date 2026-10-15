# Unreleased

### Added

### Changed

- `ails config set` accepts every setting that holds a name, a list of names or true/false: `default_agent`, `disabled_rules`, `exclude_dirs`, `exclude_files`, `generic_scanning`, `heal_exclude` and `packages`. With `--global` it accepts the same settings except `heal_exclude`, which only the project files carry.
- `<!-- ails-disable-line format -->` and `<!-- ails-disable-line bold -->` no longer silence anything: name the rule, `CORE:E:0003`, or its slug, as for every other rule.
- `CORE:C:0060` (Broad Conditional Scope) recognizes an instruction that opens with any condition word, such as `once`, `until`, `while`, `provided` or `assuming`, not only `when`, `if`, `unless`, `before` and `after`.
- `CORE:C:0058` (One Instruction Per Sentence) treats `…` and a closing quotation mark as the end of a sentence, so two sentences joined that way are no longer reported as one packed sentence.
- Heal splits a paragraph that contains an abbreviation such as `e.g.` at its real sentence ends, instead of leaving the whole paragraph alone.
- A fix in a heal plan of a kind this version does not know is left out with a warning naming it, instead of being listed as a line that needs a decision.
- A message from reporails with a level or kind this version does not know is shown as a plain information notice, with a warning in the log, instead of being dropped; a finding from the server with a severity this version does not know is shown as information, with a warning in the log.
- MCP `preflight` gives each rule's type.
- The first `ails check` after upgrading reads every instruction file again instead of reusing what an earlier version stored, so it takes longer once.
- `ails test --lint` reports every field of a rule's `rule.md` that a run rejects, all at once and each as its own finding naming the file and the field: `required_frontmatter` when the field is missing, `invalid_frontmatter` when its value is not accepted, such as an unknown `category`. An empty `id`, `slug`, `title` or `severity` is reported as missing. A check in `checks.yml` whose `severity` is not `critical`, `high`, `medium`, `low` or `info` is reported when the rule loads, naming the file and the check, and the rule is left out of the run.

### Fixed

- `disabled_rules` turns a rule off for every check that reports it. A rule listed there no longer shows up from the checks on each instruction (such as `CORE:E:0003` for a code name without backticks or bold on an instruction) or from what the server sends (its findings, the per-file counts on a free plan and the cross-file repetitions and overlaps), and a rule your agent's rule set leaves out is not reported either. `ails-disable-line` still silences a single line.
- A config file that cannot be read stops `ails check` with an error naming the file, the line and the problem, and exit code 2, instead of running on defaults without saying so. This covers `.ails/config.yml`, `.ails/config.local.yml` and `~/.reporails/config.yml`. `ails config get`, `set` and `list` read the file the same way `ails check` does, so both give the same answer for the same file, and `ails config set` no longer overwrites a file it cannot read. MCP `validate` returns the error as `config_unreadable` with the same message, and `heal_apply` replies with that message.
- `packages` loads the rule packages it lists. A package is a folder of rules in `.ails/packages/<name>/` or `~/.reporails/packages/<name>/`; its rules run with the bundled rules under their own ID prefix (`MYPACK:S:0001`), a package rule's `depends_on` is honored, and `disabled_rules` turns package rules off. A listed package that is in neither folder, or a package rule that reuses a bundled rule's ID, stops the run with an error naming it. Before, the setting was read and nothing was loaded.
- A rule whose `checks.yml` lists an entry that is not a mapping no longer crashes every command that loads it. The rule is left out with a warning naming the file and the problem, and `ails test --lint` reports the same problem. A rule whose `checks.yml` cannot be read, is not valid YAML, is not a mapping or is not UTF-8 text, or whose `rule.md` is not UTF-8 text, is left out the same way, instead of loading with no checks or stopping the run.
- A config setting that takes a list of names (`exclude_dirs`, `exclude_files`, `disabled_rules`, `heal_exclude`, `packages`) stops `ails check` with an error naming the file, the setting and the item when its value is not a list or an item is not text, such as an unquoted `2024`, instead of crashing or ignoring the setting. `agents` and `surfaces` stop the run the same way when they, or one of their entries, are not a mapping.
- When heal writes a file and the file cannot be read again to check the fix, heal puts the original back and lists it as put back, instead of stopping with an error and leaving the written file unchecked.

### Removed

- `ails test --score`: it reported 0.0 for every rule.

- The `reporails_cli` package no longer exports `__version__` (`ails version` and `importlib.metadata.version("reporails-cli")` report it), `ValidationResult`, `JudgmentRequest` or `JudgmentResponse`, and `formatters.json.format_result` / `format_score` and `formatters.github.format_result` / `format_annotations` are gone; no command produced or called them.
- The `reporails_cli` and `reporails_cli.core` packages no longer re-export names from their modules; import a name from the module that defines it.

### Internal

- The source passes pylint with no findings, and the pylint gate now fails on any new one.
- Code that no command reached is removed.
- `ails check` no longer reads `.ails/backbone.yml` or scans the root instruction file for values no check uses.
- Tests: two exclusion tests compare paths the same way on Windows.
- Tests: the marker check counts a module-level marker list, as pytest does, so each test carries exactly one lane.
- Each set of names the code compares against (formats, charges, severities and others) is defined once as a typed set of values, and a build check fails on a second copy.
- A build check fails on a function, class, record field or defaulted parameter that only tests reach; code that only tests reached is removed.
- The source is strictly typed: an untyped value appears only where a file, a reply or a third-party object is read, and the type check fails on any other.
- The maintainer command that keeps rule word lists in step with their patterns says why it leaves an entry unchanged, refuses a one-word list, a blank word, a word that would change the pattern's structure and a pattern that does not compile, names every pattern it cannot update, and reports a word list or `checks.yml` that is not UTF-8 text instead of stopping; extracting word lists names a `checks.yml` it cannot read instead of skipping it silently.
- Each file the cli reads (a rule's `checks.yml`, an agent's `config.yml`, a rule's word list, the config and lexicon files) has one reader, and a build check fails on a second one. An agent `config.yml` that cannot be read is skipped with a warning naming the file and the problem.

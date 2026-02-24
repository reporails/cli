# Features

Comprehensive feature inventory of the reporails CLI.

## Commands

Core workflow:

| Command   | Purpose                                                          |
|-----------|------------------------------------------------------------------|
| `check`   | Validate instruction files against rules — score, level, violations |
| `heal`    | Auto-fix deterministic violations (adds missing sections)        |
| `explain` | Show rule details — title, category, checks, description        |
| `install` | Configure MCP server for detected agents                        |

Configuration:

| Command   | Purpose                                                 |
|-----------|---------------------------------------------------------|
| `config`  | Get/set/list project configuration                      |
| `update`  | Update rules framework, recommended rules, or CLI itself |
| `version` | Show CLI, framework, and recommended rules versions     |

Development (rule authors and contributors):

| Command | Purpose                                                        |
|---------|----------------------------------------------------------------|
| `test`  | Rule development harness — fixture validation, coverage, scoring |
| `map`   | Discover project structure and agents, generate backbone.yml   |
| `sync`  | Sync rule definitions from framework repo                      |

Plumbing (hidden from `--help`, used by MCP and scripts):

| Command   | Purpose                            |
|-----------|------------------------------------|
| `dismiss` | Suppress semantic findings in cache |
| `judge`   | Batch-cache semantic verdicts      |

## Agent Support

7 agents: **Claude**, **Cursor**, **Windsurf**, **Copilot**, **Aider**, **Codex**, **Generic**. Each with its own instruction patterns, config locations, rule/directory patterns, and template variables. Agent-specific rule overrides without forking rules.

## Validation Engine

- **Two-pass architecture** — capability detection (level) then rule validation
- **Three check types** — mechanical (Python functions), deterministic (regex), semantic (LLM judgment)
- **Interleaved execution** — checks within a rule execute sequentially, M/D/S can mix
- **Ceiling system** — rule type constrains permitted check types
- **Batch SARIF** — all regex runs once, results distributed per-rule
- **Semantic short-circuit** — skips LLM when no evidence from cheaper checks

## Capability Levels (L0-L6)

Filesystem + content feature detection maps projects to capability levels. Cumulative ladder: L1 (basic file) through L6 (dynamic context, MCP, persistence). Orphan detection shows "L3+" when advanced features exist without intermediate levels.

## Scoring

- 0-10 scale, per-rule weight cap (2.5), severity weights (critical 5.5, high 4.0, medium 2.5, low 1.0)
- Category breakdown: Structure, Content, Efficiency, Maintenance, Governance
- Friction estimation: none → small → medium → high → extreme
- Delta comparison with previous scan

## Output Formats

- **text** — colored terminal with scorecard box, violations, scope line
- **json** — machine-readable full results
- **github** — `::error`/`::warning` workflow annotations + JSON
- **compact** — one-line summary
- **mcp** — JSON + semantic workflow instructions for Claude

## Caching

- **Judgment cache** — three-tier (content hash → structural hash → invalidate)
- **Dismissal cache** — deterministic violations cached as pass
- **File map cache** — instruction file discovery
- **Rule cache** — parsed rule definitions
- **Analytics** — per-project scan history (score trends, timing)

## Auto-fix (Heal)

5 deterministic fixers: Constraints section, Commands section, Testing section, structured headings, Project Structure section. Idempotent, reports remaining violations and pending semantic rules.

## GitHub Action

Composite action with inputs for path, strict mode, min-score gate, agent, exclude-dirs, experimental. Outputs score, level, violations, full JSON. Inline PR annotations.

## Configuration

Project config in `.reporails/config.yml` with: `default_agent`, `exclude_dirs`, `disabled_rules`, `experimental`, `recommended`, `framework_version`.

Global config in `~/.reporails/config.yml` with: `default_agent`, `recommended`. Project values override global defaults. Use `--global` flag on `config set/get/list` commands.

## Distribution

- npm wrapper (`npx @reporails/cli`) and PyPI (`uvx reporails-cli`)
- Auto-init downloads rules framework on first run
- Ephemeral (npx/uvx) and persistent install detection
- Self-update with install method detection (uv, pip, pipx, dev)

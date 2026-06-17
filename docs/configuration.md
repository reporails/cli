---
title: "Configuration"
description: "Disabling rules, project / global config, exclude paths"
version: "0.5.11"
last_updated: 2026-06-17
---

# Configuration

Reporails *provides* two configuration surfaces: global (per-user) and project (per-repo). Project config wins where both define the same key — global supplies the defaults, project overrides per-repo.

## Project config — `.ails/config.yml`

Lives at the root of your repo.

```yaml
default_agent: claude              # Which agent's rules to run by default
exclude_dirs: [examples]           # Extra directory names to skip during discovery (added to the built-in defaults below)
disabled_rules: [CORE:C:0010]      # Rule IDs to disable entirely
overrides:                         # Per-rule severity overrides
  CORE:S:0005:                     # Identity Fields In Frontmatter
    severity: low                  # Downgrade from default
```

Set values from the command line instead of editing the file:

> Running these in the `PROJECT_ROOT`

```bash
ails config set default_agent claude
ails config set exclude_dirs examples,third_party
```

### Built-in directory excludes

Reporails always skips these directory names during discovery, no matter where they appear in the tree. Without these defaults, the scan would descend into vendored trees and build output and pick up third-party instruction files (e.g. a `CLAUDE.md` shipped inside `node_modules/<pkg>/`) you didn't author:

| Category     | Directory names                                                                              |
|--------------|----------------------------------------------------------------------------------------------|
| VCS          | `.git`, `.svn`, `.hg`                                                                        |
| Python       | `__pycache__`, `.venv`, `venv`, `.env`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`        |
| JS / TS      | `node_modules`                                                                               |
| Build output | `dist`, `build`, `target`, `out`                                                             |
| Data         | `data`, `datasets`                                                                           |
| Vendored     | `vendor`                                                                                     |
| IDE / OS     | `.idea`, `.vscode`                                                                           |

Anything you add to `exclude_dirs` is *additional* — the built-ins always apply.

## Global config — `~/.reporails/config.yml`

Applies to every project.

```yaml
default_agent: claude
auto_update_check: true
```

The global file accepts every field `.ails/config.yml` does (`disabled_rules`, `exclude_dirs`, `exclude_files`, `overrides`, `rule_thresholds`, `generic_scanning`, and more) — project values win per-key where the two overlap.

Set values from the command line:

```bash
ails config set --global default_agent claude
ails config set --global auto_update_check false
```

Project config wins where it overlaps with global. So if global says `default_agent: claude` and the repo's `.ails/config.yml` says `default_agent: cursor`, that repo runs the Cursor rule set.

## Disabling rules

The single most common config change is disabling rules you disagree with:

```yaml
# PROJECT_ROOT/.ails/config.yml
disabled_rules:
  - CORE:C:0010   # Build And Test Commands
  - CORE:S:0005   # Identity Fields In Frontmatter
```

Browse the full rule reference at [reporails.com/rules](https://reporails.com/rules) to look up each rule's body and pass / fail examples before disabling — sometimes the rule's intent fits your project but the surface form doesn't, and a severity override (below) reads better than a disable. `ails explain CORE:C:0010` shows the rule body inline from the CLI when you already know the ID.

## Excluding directories

`exclude_dirs` is a list of directory *names* (not paths). Any directory matching one of these names is skipped no matter where it appears. The setting exists because the discovery walk scans every directory looking for instruction files — without an exclude list it would descend into vendored trees (`node_modules`, `vendor/`), build output (`dist/`, `target/`), and data dumps (`data/`), surfacing third-party `CLAUDE.md` / `AGENTS.md` files you didn't author and slowing the scan.

The [built-in list above](#built-in-directory-excludes) already covers the common cases. Add to `exclude_dirs` only when your project has a non-standard tree:

```yaml
exclude_dirs:
  - examples
  - third_party
```

For one-off runs, pass `--exclude-dirs` on the command line:

```bash
ails check --exclude-dirs examples --exclude-dirs third_party
```

## Excluding individual files

`exclude_files` targets *specific files* rather than directory names. Each entry is a glob matched against the file path **relative to the project root**, so you can name an exact file, files one level down, or any file by basename:

```yaml
# PROJECT_ROOT/.ails/config.yml
exclude_files:
  - .claude/agents/lead.md   # that exact file
  - .claude/skills/*/SKILL.md # each skill's SKILL.md (one level down)
  - "**/lead.md"             # any lead.md, anywhere
```

The common case is a project that symlinks coding-agent harness artifacts (skills, agents, rules) in from another repo. Those files are authored and linted where they live, so scoring them here just adds noise — list their paths under `exclude_files` to drop them. Selection is by path, not by "is a symlink", because symlinks are also used legitimately (e.g. `CLAUDE.md → AGENTS.md`).

Patterns use [`pathlib` glob semantics](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.match): each `*` and `**` segment matches **exactly one** path component — it is *not* a recursive `git`-style globstar. So a pattern matches at a fixed depth: `.claude/skills/*/SKILL.md` and `.claude/skills/**/*` both reach files exactly one directory below `skills/`, not files nested deeper. To cover several depths, list one pattern per depth. This matches the convention the `surfaces` include / exclude patterns already use.

A bare `**` or `**/*` matches *every* file in the project — it drops all instruction files and the scan exits with `No instruction files found`. Always anchor the pattern to a path prefix (`.claude/skills/...`).

For one-off runs, pass `--exclude-files`:

```bash
ails check --exclude-files ".claude/skills/**/*" --exclude-files ".claude/agents/lead.md"
```

Explicitly targeting an excluded file still scans it — `ails check ./.claude/agents/lead.md` overrides the exclusion, since exclusion only applies to discovery.

## Per-surface include / exclude

Each agent has a set of *surfaces* — `main` (the primary instruction file), `nested_context` (subdirectory variants), `rules`, `skills`, `agents`, etc. The `surfaces` key lets you adjust the glob patterns each surface scans, without modifying the bundled framework configs:

```yaml
# .ails/config.yml
surfaces:
  cursor.rules:
    exclude: ["**/draft/**"]            # drop matches under draft/ from Cursor rules
  claude.skills:
    include: [".github/skills/**/SKILL.md"]   # also scan .github/skills/ for Claude
  codex.main:
    exclude: ["**/legacy/AGENTS.md"]    # drop legacy AGENTS.md from Codex's main candidates
```

Keys are `<agent_id>.<file_type>` (e.g. `cursor.rules`, `claude.main`, `codex.nested_context`). Each entry may set:

- `include`: additional glob patterns to scan **on top of** the agent's bundled patterns.
- `exclude`: glob patterns whose matches are dropped from the surface's results.

Patterns match relative to the project root (the directory you ran `ails check` from).

## Codex fallback filenames

Codex supports `project_doc_fallback_filenames` in its own `~/.codex/config.toml` to recognize alternative instruction filenames (e.g. `TEAM_GUIDE.md`, `.agents.md`). Reading that user-home config from the validator is fragile — CI users have different homes — so Reporails reads the same setting from the project's own `.ails/config.yml`:

```yaml
# .ails/config.yml
agents:
  codex:
    fallback_filenames: ["TEAM_GUIDE.md", ".agents.md"]
```

These filenames are added as `**/<filename>` to Codex's `main` surface — they classify the same way `AGENTS.md` does and pick up the same rules.

## Local overrides — `.ails/config.local.yml`

Personal or CI-specific config that should not be committed goes in `.ails/config.local.yml`. The file is layered on top of `.ails/config.yml`:

- Object keys merge recursively.
- Array keys extend (the local list is appended to the committed list).
- Scalar keys are replaced.

```yaml
# .ails/config.local.yml — gitignored
surfaces:
  claude.main:
    exclude: ["**/legacy/CLAUDE.md"]    # I personally don't care about legacy/
```

When `ails config set …` writes `.ails/config.yml`, it also writes `.ails/.gitignore` listing `config.local.yml` and `.gitignore` itself — the gitignore is per-machine scaffolding (recreated on the next `ails config set`) and doesn't need to be committed. If you create `.ails/` manually, add the two lines yourself:

```
# .ails/.gitignore
.gitignore
config.local.yml
```

## Per-rule thresholds

Some rules ship with a built-in `min_lines` gate so small files do not get flagged for issues that only matter at scale. For example, `CORE:S:0013 scope-fields-in-frontmatter` ships with `min_lines: 30` — a 5-line rule file won't fail it. You can raise or lower the threshold per project under `overrides.rule_thresholds`:

```yaml
# .ails/config.yml
overrides:
  rule_thresholds:
    CORE:S:0013:
      min_lines: 50          # require 50+ lines before this rule fires
    CORE:C:0034:
      min_lines: 0           # always fire, even on tiny files
```

Any deterministic check that declares a `min_lines:` entry in its `checks.yml` can be tuned this way — see `ails explain <rule_id>` for which rules expose the gate.

## Generic-class scanning (opt-in)

By default, `ails check` only validates files that match one of the agent's declared instruction-file patterns. Set `generic_scanning: true` to extend coverage to any reachable Markdown file:

```yaml
# .ails/config.yml
generic_scanning: true
```

When on, the discovery walker follows links out of classified files (bounded depth, cycle-safe, tree-bound), and distinguishes two kinds of reached file by *how* they were reached:

- **`@`-import-reached** files (`file_type: generic`) — pulled in by an `@`-import directive. The agent eagerly auto-loads these, so Reporails does too: they are scored and shown under an `Imported` surface that counts toward the Quality score.
- **Markdown-link-reached** files (`[text](path)`, `file_type: referenced`) — discoverable but not loaded. The agent only reads them if it chooses to follow the link, so Reporails surfaces them in a labeled `Referenced` findings panel only: no score bar, and not counted in the headline.

Structural and formatting rules (charge ordering, direction imbalance, formatting hygiene) still fire on both kinds; main-shape rules (tech stack, MCP docs) do not. Default is off so anonymous tryouts against third-party repos stay quiet.

## Severity overrides

Severity is what makes a finding "critical" vs "info". Default severity comes from the rule itself; you can override it per project:

```yaml
overrides:
  CORE:S:0005:                     # Identity Fields In Frontmatter
    severity: info                  # I don't care about this one — keep it visible but don't weight it
  CORE:G:0001:                     # Vcs Tracked
    severity: critical             # I really care about this one — escalate
```

Valid severity values: `critical`, `high`, `medium`, `low`, `info`.

## Strict mode and minimum score

By default, `ails check` always exits 0 (so it doesn't break workflows). To make it exit non-zero on any finding:

```bash
ails check --strict
```

The CLI does not have a built-in `--min-score` flag. To gate on a minimum score, use the GitHub Action's `min-score` input — it parses the score from the JSON output and runs a post-step gate:

```yaml
- uses: reporails/cli/action
  with:
    strict: "true"            # exit 1 if any rule fires
    min-score: "7.0"          # exit 1 if score < 7.0
```

Outside the action, use `--strict` for a pass/fail gate; for score-based gating, the GitHub Action's `min-score` input is the supported path.

## Authentication

The anonymous tier requires no account. To raise rate / payload caps and unlock the full diagnostic detail, sign in:

```bash
ails auth login        # browser-based GitHub Device Flow
ails auth status       # show current tier and a redacted key prefix
ails auth token        # print the full API key (for CI export)
ails auth logout       # remove stored credentials
```

Credentials are stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX; Windows logs a warning, secure the file manually).

For CI, capture the API key with `ails auth token` and add it to your CI provider's secret store as `AILS_API_KEY` (or pass it via the GitHub Action's `api-key` input — see the [GitHub Actions section in the README](https://github.com/reporails/cli#readme)).

## Output format

Pick output format per-run:

```bash
ails check -f text       # default — human-readable (see the Quick Start in the README for an example)
ails check -f json       # machine-readable JSON
ails check -f github     # GitHub Actions inline annotations
```

JSON output is one object per run, grouping findings under `files` keyed by path, plus aggregate `stats` and (when present) cross-file blocks. Tier-conditional fields are noted below.

```json
{
  "offline": false,
  "files": {
    "CLAUDE.md": {
      "findings": [
        {
          "line": 18,
          "severity": "warning",
          "rule": "CORE:C:0034",
          "category": "coherence",
          "leverage": "conditional",
          "message": "Missing tech stack declaration"
        }
      ],
      "count": 5,
      "regime": { "named": "...", "within_capacity": true, "confidence": 0.87 }
    }
  },
  "stats": { "total_findings": 21, "errors": 0, "warnings": 16, "infos": 5, "cross_file_conflicts": 0, "cross_file_repetitions": 0 }
}
```

What differs by tier:

| Field                                              | Anonymous | Signed in                           |
|----------------------------------------------------|-----------|-------------------------------------|
| `files.<path>.findings[].fix`                      | omitted   | included when the rule has fix text |
| `cross_file[]` (full detail, line / type per pair) | omitted   | included                            |
| `cross_file_coordinates[]` (counts per file pair)  | included  | omitted                             |
| `pro{}` (summary of hints)                         | omitted   | included when present               |

Always present, regardless of tier: `offline`, `files{}`, `stats`, `tier`, `top_rules`. `surface_health[]` is added when surfaces are populated; each entry carries `name`, `score`, `file_count`, `finding_count`, and a per-category `category_breakdown` map.

Two additive fields enrich the output when the analysis service has data for the run. Both are **additive and backward-compatible** — existing JSON consumers and CI baselines that ignore them keep working unchanged:

- **Per-file `regime`** — a `files.<path>.regime` object with `named`, `within_capacity`, and `confidence`. It is a structural read of the file; it is absent on offline runs (no analysis service).
- **Per-finding `leverage`** — a `files.<path>.findings[].leverage` tier of `gate_mover`, `conditional`, or `cosmetic`, indicating how much fixing the finding is likely to move the score. The raw `severity` field is unchanged. See [Score Guide → How findings are triaged by leverage](score-guide.md#how-findings-are-triaged-by-leverage).

GitHub annotations format emits one workflow command per finding so warnings appear inline on the diff in pull requests:

```
::warning file=CLAUDE.md,line=18,col=1::Missing tech stack declaration (CORE:C:0034)
::warning file=CLAUDE.md,line=42,col=1::Missing MCP documentation (CORE:C:0027)
```

---

[← Tiers and Limits](tiers.md) · Configuration · [Score Guide →](score-guide.md)

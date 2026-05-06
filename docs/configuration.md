---
title: "Configuration"
description: "Disabling rules, project / global config, exclude paths"
version: "0.5.7"
last_updated: 2026-05-06
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

Outside the action, wrap `ails check -f json` in a script that parses the `score` field and exits accordingly.

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
          "message": "Missing tech stack declaration"
        }
      ],
      "count": 5
    }
  },
  "stats": { "total": 21, "errors": 0, "warnings": 16, "info": 5 }
}
```

What differs by tier:

| Field                                              | Anonymous | Signed in                           |
|----------------------------------------------------|-----------|-------------------------------------|
| `files.<path>.findings[].fix`                      | omitted   | included when the rule has fix text |
| `cross_file[]` (full detail, line / type per pair) | omitted   | included                            |
| `cross_file_coordinates[]` (counts per file pair)  | included  | omitted                             |
| `pro{}` (summary of hints)                         | omitted   | included when present               |

Always present, regardless of tier: `offline`, `files{}`, `stats`. `surface_health[]` is added when surfaces are populated.

GitHub annotations format emits one workflow command per finding so warnings appear inline on the diff in pull requests:

```
::warning file=CLAUDE.md,line=18,col=1::Missing tech stack declaration (CORE:C:0034)
::warning file=CLAUDE.md,line=42,col=1::Missing MCP documentation (CORE:C:0027)
```

---

[← Tiers and Limits](tiers.md) · Configuration · [Score Guide →](score-guide.md)

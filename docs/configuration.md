---
title: "Configuration"
description: "Disabling rules, project / global config, exclude paths"
version: "0.6.0"
last_updated: 2026-09-20
---

# Configuration

Reporails *provides* two configuration surfaces: global (per-user) and project (per-repo). Global supplies the defaults and project overrides them per-repo: a single-value setting takes the project value, and a list setting combines both files.

## Project config — `.ails/config.yml`

Lives at the root of your repo.

```yaml
default_agent: claude              # Which agent's rules to run by default
exclude_dirs: [examples]           # Extra directory names to skip during discovery (added to the built-in defaults below)
disabled_rules: [CORE:C:0010]      # Rule IDs to disable entirely
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
```

The global file accepts every field `.ails/config.yml` does (`disabled_rules`, `exclude_dirs`, `exclude_files`, `rule_thresholds`, `generic_scanning`, and more) — the two files are combined, and the project file wins where both set the same thing. List settings (`disabled_rules`, `exclude_dirs`, `exclude_files`, `packages`) are combined: a global file that disables one rule and a project file that disables another disable both. Settings that hold a single value (`default_agent`, `generic_scanning`) take the project value when the project sets one. Keyed settings (`rule_thresholds`, `agents`, `surfaces`) are merged key by key, with the project value replacing the global one for the same key.

Set values from the command line:

```bash
ails config set --global default_agent claude
```

For a single-value setting the project value wins. So if global says `default_agent: claude` and the repo's `.ails/config.yml` says `default_agent: cursor`, that repo runs the Cursor rule set.

## Environment variables

| Variable             | What it does                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AILS_PLUGIN_SOURCE` | Where `ails install` adds the reporails plugin from, for Claude Code and Codex. A local folder or `owner/repo`; unset, it is `reporails/plugin`. |

## Model cache

Reporails analyzes your instructions with a bundled model that is **not** shipped inside the package — it is downloaded once, on the first run that needs it, into `~/.reporails/cache/models/`. Because the cache lives in your home directory (not the ephemeral `npx` package cache), the ~275 MB download happens once per machine and survives every `npx` cold start; a fresh `npx` re-pulls only the small package. Every run after the first is silent and offline.

The first run needs network access. If it cannot reach the download host, `ails check` stops with a clear error and exit code 2 and leaves nothing half-downloaded behind. `ails check` starts the download only when there are instruction files to check (the MCP server starts it when it launches), and a slow connection is not cut off by the check's time limit. Checks started at the same time download the model once. Every downloaded file is verified before it is used. If a model file later goes missing, the next run restores it and downloads only what it needs. The cache keeps the current and the previous model version. To fetch from your own mirror or an internal cache, point the download at it:

```bash
export AILS_MODEL_URL="https://mirror.example.com/reporails-model"
```

`AILS_MODEL_URL` is the base URL; Reporails appends each model file's name to it, flattening any `/` in the file's own path to `__`, so a mirror serves one flat directory. To build one, run a check once on a machine that can reach the default host, then copy every file under `~/.reporails/cache/models/<version>/` to the mirror, naming each file by its path inside that folder with every `/` replaced by `__`. Unset, the model downloads from `https://models.reporails.com` — allow that host through a firewall or proxy for the first run. When you are signed in (`ails auth login` or `AILS_API_KEY`), that download carries your API key; the key is never sent to an `AILS_MODEL_URL` host.

To never download, set `AILS_MODEL_OFFLINE=1`. Reporails then uses a model already on disk and, without one, runs without the content checks.

### Caching the model in CI

A CI job starts on a fresh machine with an empty home directory, so without a cache every run downloads the model again (~275 MB). With a cache, later runs restore the model from your CI's cache storage and do not contact the Reporails download host at all.

**With the [GitHub Action](#github-action)** there is nothing to set up. The action:

- downloads the model on the first run and saves it in the repository's Actions cache;
- restores it on every later run on the same runner OS, until a CLI update brings a new model;
- saves it even when the check fails, for example on `strict` findings;
- keeps it apart from the per-file analysis, so editing instruction files never saves the model again.

**The model still downloads**, even with a cache, on:

- the first run in a repository, and the first run after a CLI update that brings a new model;
- jobs that start together before any of them has saved the model — each downloads once;
- a run after GitHub has dropped the cached copy. GitHub removes an entry that has not been used for a week, and a run can only use entries saved on its own branch, its pull request's base branch, or the default branch, so a new branch downloads once unless the model is already saved on one of those.

**In a workflow that runs `ails` directly**, cache `~/.reporails/cache/models` yourself. Pin the CLI version and use it in the cache key: the model changes only when a new CLI release brings a new model version, so most version bumps restore the same cached model and an occasional one downloads it once and caches it again.

```yaml
env:
  REPORAILS_VERSION: "0.6.0"
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - run: pip install "reporails-cli==${{ env.REPORAILS_VERSION }}"
  - uses: actions/cache@v4
    with:
      path: ~/.reporails/cache/models
      key: reporails-model-${{ runner.os }}-${{ env.REPORAILS_VERSION }}
  - run: ails check
```

Install a pinned version as shown (or `uvx --from "reporails-cli==<version>" ails check` where `uv` is set up). `npx @reporails/cli` always runs the latest CLI whatever version you give it, so it cannot be pinned for this key. `actions/cache` saves only when the job succeeds: a job that fails on `ails check --strict` findings saves nothing, and the next run downloads the model again. The GitHub Action keeps the model even when the check fails.

When `ails` downloads the model inside GitHub Actions, it prints a line pointing to this section.

## Disabling rules

The single most common config change is disabling rules you disagree with:

```yaml
# PROJECT_ROOT/.ails/config.yml
disabled_rules:
  - CORE:C:0010   # Build And Test Commands
  - CORE:S:0005   # Identity Fields In Frontmatter
```

Browse the full rule reference at [reporails.com/rules](https://reporails.com/rules) to look up each rule's body and pass / fail examples before disabling — disabling is the right call when the rule's intent doesn't fit your project; complying is the right call when the intent matches but you weren't reaching it. `ails explain CORE:C:0010` shows the rule body inline from the CLI when you already know the ID.

## Suppressing one finding on one line

`disabled_rules` turns a rule off everywhere. When a single line is an intentional, reviewed exception but the rule is still worth running everywhere else, mark just that line with an inline directive instead:

```markdown
## Always run the tests before committing  <!-- ails-disable-line CORE:C:0047 -->
```

The directive is an HTML comment, so it stays invisible when the file renders. It suppresses **only** the named rule **only** on its own line — the same rule still fires on every other line, and other rules on the annotated line still fire. Name several rules with a space- or comma-separated list:

```markdown
Some heading line  <!-- ails-disable-line CORE:C:0047, CORE:C:0042 -->
```

Use the rule ID shown next to the finding in `ails check` output (e.g. `CORE:C:0047`); the rule's slug works too. A directive that names no rule suppresses nothing — suppression is always targeted, so it stays auditable in review. The directive text never affects how the rest of the line is analyzed.

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
  - .claude/agents/reviewer.md # that exact file
  - .claude/skills/*/SKILL.md # each skill's SKILL.md (one level down)
  - "**/reviewer.md"         # any reviewer.md, anywhere
```

The common case is a project that symlinks coding-agent harness artifacts (skills, agents, rules) in from another repo. Those files are authored and linted where they live, so scoring them here just adds noise — list their paths under `exclude_files` to drop them. Selection is by path, not by "is a symlink", because symlinks are also used legitimately (e.g. `CLAUDE.md → AGENTS.md`).

Patterns use [`pathlib` glob semantics](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.match): each `*` and `**` segment matches **exactly one** path component — it is *not* a recursive `git`-style globstar. So a pattern matches at a fixed depth: `.claude/skills/*/SKILL.md` and `.claude/skills/**/*` both reach files exactly one directory below `skills/`, not files nested deeper. To cover several depths, list one pattern per depth. This matches the convention the `surfaces` include / exclude patterns already use.

A bare `**` or `**/*` matches *every* file in the project — it drops all instruction files and the scan exits with `No instruction files found`. Always anchor the pattern to a path prefix (`.claude/skills/...`).

For one-off runs, pass `--exclude-files`:

```bash
ails check --exclude-files ".claude/skills/**/*" --exclude-files ".claude/agents/reviewer.md"
```

Explicitly targeting an excluded file still scans it — `ails check ./.claude/agents/reviewer.md` overrides the exclusion, since exclusion only applies to discovery.

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

A fallback file is checked where Codex reads it: in a directory that has no `AGENTS.md` (and no `AGENTS.override.md`), at the project root or in a subfolder. There it classifies the same way an `AGENTS.md` in that directory would and picks up the same rules. A fallback file that sits beside an `AGENTS.md` is not read by Codex, so it is not checked.

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

Some rules ship with a built-in `min_lines` gate so small files do not get flagged for issues that only matter at scale. For example, `CORE:S:0013 scope-fields-in-frontmatter` ships with `min_lines: 30` — a 5-line rule file won't fail it. You can raise or lower the threshold per project under `rule_thresholds`:

```yaml
# .ails/config.yml
rule_thresholds:
  CORE:S:0013:
    min_lines: 50            # require 50+ lines before this rule fires
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

Structural and formatting rules still fire on both kinds; main-shape rules (tech stack, MCP docs) do not. Default is off so anonymous tryouts against third-party repos stay quiet.

## Strict mode and minimum score

By default, `ails check` always exits 0 (so it doesn't break workflows). To make it exit non-zero on any finding:

```bash
ails check --strict
```

The CLI does not have a built-in `--min-score` flag. To gate on a minimum score, use the GitHub Action's `min-score` input — it parses the score from the JSON output and runs a post-step gate:

```yaml
- uses: reporails/cli/action@0.6.0
  with:
    strict: "true"            # exit 1 if any rule fires
    min-score: "7.0"          # exit 1 if score < 7.0
```

Outside the action, use `--strict` for a pass/fail gate; for score-based gating, the GitHub Action's `min-score` input is the supported path.

When `min-score` is set, the gate fails CLOSED if the diagnostics server rejected the run, timed out, or was unreachable — `::error::Quality gate cannot run: diagnostics server unavailable (<reason>)`, exit 1 — rather than silently skipping the check on a missing score. It only prints the offline-run warning and exits 0 when there genuinely was no score to gate on (no server call was made at all) and `min-score` was not configured.

## Authentication

The anonymous tier requires no account, and signing in is free. A free account does not raise your rate or payload caps — anonymous and signed-in free accounts share the same limits. Signing in gives you an identity (so you can subscribe and manage the subscription) and enables `ails check --heal`, which refuses to write files for an anonymous run. Raising the caps and unlocking the full diagnostic detail is what a Pro subscription adds — see [Tiers and Limits](tiers.md).

```bash
ails auth login        # browser-based GitHub Device Flow
ails auth status       # show whether you're signed in, the key source, and a redacted key prefix (the tier is shown for a stored sign-in; for a key held in `AILS_API_KEY` it reads `Tier: (resolved at check time)`)
ails auth token        # print the full API key (for CI export)
ails auth logout       # remove stored credentials
```

Credentials are stored in `~/.reporails/credentials.yml` (`chmod 0600` on POSIX; Windows logs a warning, secure the file manually).

For CI, capture the API key with `ails auth token` and add it to your CI provider's secret store as `AILS_API_KEY` (or pass it via the GitHub Action's `api-key` input — see the [GitHub Actions section in the README](https://github.com/reporails/cli#readme)).

## GitHub Action

`reporails/cli/action` is a composite action that installs the CLI, runs `ails check --format github` (which emits inline annotations plus the same JSON document as `-f json` on its trailing line), and exposes the result. It keeps the analysis model and the per-file analysis between runs, so a later run does not download the model again and re-analyzes only the instruction files that changed. The model is kept even when the check fails, for example on `strict` findings. Every input it accepts:

| Input          | Default | What it does                                                                                      |
|----------------|---------|---------------------------------------------------------------------------------------------------|
| `path`         | `.`     | Path to validate — point it at a subdirectory to scan only that tree.                             |
| `strict`       | `false` | Fail the step on any finding.                                                                     |
| `min-score`    | (empty) | Minimum score (0–10). Fails the step when the run scores below it.                                |
| `agent`        | (empty) | Agent to score against (`claude`, `cursor`, …). Empty resolves from project config, then a generic fallback. |
| `exclude-dir`  | (empty) | Comma-separated directory *names* to skip (e.g. `vendor,dist`), added to the built-in excludes.   |
| `version`      | (empty) | CLI version to install (e.g. `0.6.0`). Empty installs the latest release.                         |
| `from-source`  | `false` | Internal — installs the CLI from a local checkout so the action can test itself. Leave it `false`. |
| `api-key`      | (empty) | Your API key, normally `${{ secrets.REPORAILS_API_KEY }}`. Empty runs anonymously.                |
| `server-url`   | (empty) | Overrides the diagnostic endpoint. Empty uses production — set it only for a staging deployment.  |

And every output:

| Output       | What it carries                                                                 |
|--------------|-----------------------------------------------------------------------------------|
| `score`      | The Quality score (0–10).                                                        |
| `level`      | The maturity level on the `L0`–`L7` ladder — see [Capability Levels](capability-levels.md). |
| `violations` | Number of findings.                                                              |
| `result`     | The full JSON result, in the shape documented under [Output format](#output-format). |
| `server-status` | `ok` or `server-unavailable` — whether the diagnostics server actually answered this run. A `min-score` gate fails closed when `server-unavailable`, instead of silently passing on a missing score. |
| `server-error`  | The rejection/outage reason token (e.g. `rate_limit_exceeded`, `timeout`, `network_error`) when `server-status` is `server-unavailable`. Empty otherwise. |

```yaml
- uses: reporails/cli/action@0.6.0
  id: reporails
  with:
    path: ./packages/api
    api-key: ${{ secrets.REPORAILS_API_KEY }}
    exclude-dir: "vendor,dist"
    min-score: "7.0"
- run: echo "level=${{ steps.reporails.outputs.level }}"
```

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
  "server_error": null,
  "tier": "free",
  "quality": 3.2,
  "level": "L3",
  "elapsed_ms": 593.5,
  "files": {
    "CLAUDE.md": {
      "findings": [
        {
          "line": 0,
          "severity": "error",
          "rule": "CORE:S:0024",
          "category": "structure",
          "leverage": "conditional",
          "message": "Unresolved imports: docs/setup.md"
        }
      ],
      "count": 29,
      "regime": { "triage_tier": "..." }
    }
  },
  "stats": { "total_findings": 39, "errors": 2, "warnings": 35, "infos": 2, "cross_file_repetitions": 1, "cross_file_overlaps": 0 },
  "pro": { "count": 6, "errors": 2, "warnings": 3 },
  "cross_file_coordinates": [
    { "file_1": ".claude/rules/git.md", "file_2": "CLAUDE.md", "type": "repetition", "count": 1 }
  ]
}
```

The `severity` values the run *emits* are `error`, `warning`, and `info` — the same vocabulary `stats` aggregates as `errors` / `warnings` / `infos`. A CI filter on the JSON output matches `error` / `warning` / `info`.

What differs by tier — measured on the same two-file fixture (one `CLAUDE.md`, one `.claude/rules/git.md`) at each tier:

| Field                                          | Anonymous | Free (signed in) | Pro |
|-------------------------------------------------|-----------|-------------------|-----|
| `files.<path>.findings[].fix`                    | present only on findings a local deterministic check can fix on its own (3 of 39 findings on the fixture) — the server sends no remedy text to an unpaid tier | same as anonymous (3 of 39) | present on each finding that has a remedy (25 of 45 on the fixture) — not every finding carries one |
| `pro{}` (upgrade-hint summary: `count`, `errors`, `warnings`) | present when the run has hints | present when the run has hints | omitted — Pro receives the findings themselves, so there is nothing to hint at |
| `workflow{}` (ordered remediation plan: `summary`, `escape`, `locations[]`, `listed[]`) | omitted | omitted | present when the server returned one |
| `cross_file_coordinates[]` (which files, how many, no line numbers) | present when the run has cross-file findings | present when the run has cross-file findings | omitted |
| `cross_file[]` (the same pairs, with each finding's line in both files) | omitted | omitted | present when the run has cross-file findings |

Do not key a "is this a paid run?" check off `pro{}` — it is the *upgrade hint* for unpaid runs and is absent on Pro. Read `tier` (`anonymous` / `free` / `pro`; empty (`""`) when the service gave no reply, as on an offline run) instead; `workflow{}` is the paid-only payload. `workflow.locations[]` orders the project's kinds of files to rewrite (each entry carries `order`, `element`, `kind`, `loading`, `files`, `importance`, and its own `findings[]` with `remedy` text); `workflow.listed[]` names every other firing rule and why it needs no rewrite; there is no `workflow.steps[]`.

Always present, regardless of tier: `offline`, `server_error`, `tier`, `quality`, `level`, `files{}`, `stats`, `top_rules`, `elapsed_ms`. `quality` is `null` when no score was computed (an offline run). `server_error` is `null` when the server answered; when the request was rejected, timed out, or failed it carries `{status, error, message, upgrade_url, tier}` — so a designed offline run and a real outage are distinguishable rather than both reading as "no score". `surface_health[]` is added when surfaces are populated; each entry carries `name`, `score`, `file_count`, `finding_count`, and a per-category `category_breakdown` map. An entry's `type` is `repetition` (one instruction repeated nearly verbatim in two files) or `overlap` (one same-topic line pair of two files that can load together). `stats.cross_file_overlaps` counts the overlapping file pairs. `cross_file[]` and `cross_file_coordinates[]` are tier-exclusive (see the table above) and both are absent when the run has no cross-file findings.

Two additive fields enrich the output when the analysis service has data for the run. Both are **additive and backward-compatible** — existing JSON consumers and CI baselines that ignore them keep working unchanged:

- **Per-file `regime`** — a `files.<path>.regime` object with the per-file `triage_tier` token. It is a structural read of the file; it is absent on offline runs (no analysis service).
- **Per-finding `leverage`** (paid runs only) — a `files.<path>.findings[].leverage` value of `gate_mover`, `conditional`, or `cosmetic`, stating how likely clearing the finding is to raise the score: likely, maybe, or unlikely. On a Pro run the value is measured per file: `gate_mover` findings are the ones whose clearing is predicted to move that file's score most, `cosmetic` ones barely move it, and `conditional` ones sit in between. An unpaid or offline run omits the key. The raw `severity` field is unchanged. See [Score Guide → How findings are ordered by score effect](score-guide.md#how-findings-are-ordered-by-score-effect).

GitHub annotations format emits one workflow command per finding so warnings appear inline on the diff in pull requests:

```
::warning file=CLAUDE.md,line=18,title=[CORE%3AC%3A0034]::Missing tech stack declaration — list languages, frameworks, and runtimes
::warning file=CLAUDE.md,line=42,title=[CORE%3AC%3A0027]::Missing MCP documentation — describe MCP server configuration if applicable
```

The rule ID rides in `title` (URL-encoded), not in trailing parentheses, and there is no `col`. A file-level finding (one that applies to the whole file, not one line) carries no `line` key at all.

---

[← Tiers and Limits](tiers.md) · Configuration · [Score Guide →](score-guide.md)

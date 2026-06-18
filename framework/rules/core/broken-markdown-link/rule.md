---
id: CORE:S:0056
slug: broken-markdown-link
title: Markdown Link Targets Resolve
category: structure
type: mechanical
severity: high
backed_by: []
match: {format: [freeform, frontmatter]}
fix: |
  Update the link target to point to an existing path. Either fix the
  path (typo, wrong directory) or create the target file. Bare-token
  links like `[ENGINE.md](ENGINE.md)` are usually wrap-bug artifacts —
  review heal output and use a relative path the reader can follow.
---

# Markdown Link Targets Resolve

Markdown links in instruction files must resolve to existing files. Broken targets create phantom context — the agent sees the link directive but the referenced content never loads, so the file silently underdelivers compared to what its prose promises.

## Antipatterns

- **Renamed file without updating the link**: Moving `docs/setup.md` to `docs/getting-started.md` but leaving `[Setup](docs/setup.md)` in another file. The `extract_markdown_links` check finds the reference and `check_markdown_link_targets_exist` fails because the path no longer resolves.
- **Typo in relative path**: Writing `[Rules](.claude/rules/git-rules.md)` instead of `[Rules](.claude/rules/git.md)`. The link silently fails — the surrounding prose still reads as if the target loaded.
- **Link crossing repository boundary**: Referencing `[Notes](../../other-repo/CLAUDE.md)` which exists in the author's local checkout but not in CI or other contributors' working trees.
- **Reference-style definition pointing nowhere**: Defining `[setup]: docs/old-setup.md` at the bottom of the file after the target was deleted. The definition is still parsed even when no inline `[setup]` consumes it.

## Pass / Fail

### Pass

~~~~markdown
# Project Setup

See [Getting Started](docs/getting-started.md) for the install steps and
the [testing rules](.claude/rules/testing.md) for the QA gate.

[setup]: docs/getting-started.md
~~~~

### Fail

~~~~markdown
# Project Setup

See [Getting Started](docs/old-setup.md) for the install steps and
the [testing rules](.claude/rules/deleted-rule.md) for the QA gate.

[setup]: docs/old-setup.md
~~~~

## Limitations

Discovers `[text](path)` inline links and `[ref]: path` reference definitions, then resolves each target relative to the source file's directory. Skips URLs (`://`, `mailto:`), absolute paths (`/foo`), and anchor-only references (`#frag`). Does not validate that anchors exist within the target file, does not detect broken references inside fenced code blocks (lookups span the entire file content), and does not check external URLs for reachability.

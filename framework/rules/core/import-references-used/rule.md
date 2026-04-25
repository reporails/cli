---
id: CORE:S:0026
slug: import-references-used
title: "Import References Resolve"
category: structure
type: mechanical
severity: medium
backed_by:
- claude-code-imports
match: {scope: path_scoped}
---

# Import References Resolve

Every `@path` import reference in an instruction file must resolve to an existing file. Broken import references create phantom context — the agent sees the import directive but the referenced content never loads, causing silent gaps in its instruction set.

## Antipatterns

- **Importing a deleted file.** An instruction file references `@../shared/conventions.md` but the file was removed during a refactor. The agent sees the import and may hallucinate the expected content.
- **Typo in import path.** Writing `@.claude/rules/git-rules.md` instead of `@.claude/rules/git.md`. The import silently fails.
- **Importing across repository boundaries.** Referencing `@../../other-repo/CLAUDE.md` which exists locally but not in CI or other contributors' checkouts.

## Pass / Fail

### Pass

```markdown
<!-- .claude/rules/testing.md -->
@../CLAUDE.md

Use `pytest` for all tests.
```

Where `CLAUDE.md` exists at the expected relative path.

### Fail

```markdown
<!-- .claude/rules/testing.md -->
@../deleted-file.md

Use `pytest` for all tests.
```

Where `deleted-file.md` does not exist.

## Limitations

Uses `extract_imports` to discover `@path` references, then `check_import_targets_exist` to verify each target resolves. Does not check whether the imported content is semantically relevant — only that the file exists.

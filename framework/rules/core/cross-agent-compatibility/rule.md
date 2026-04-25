---
id: CORE:C:0026
slug: cross-agent-compatibility
title: Cross Agent Compatibility
category: coherence
type: deterministic
severity: high
backed_by: [agentic-coding-adoption-github, claude-md-guide, claude-md-optimization-study,
  claudemd-best-practices-backbone-yml-pattern, enterprise-claude-usage, fowler-pushing-ai-autonomy,
  microsoft-awesome-copilot-blog, osmani-ai-coding-workflow, sewell-codex-vs-claude]
match: {type: main}
---
# Cross Agent Compatibility

Multi-agent projects must have compatible instruction sets — shared instructions must be agent-neutral, with agent-specific content isolated to dedicated files.

## Antipatterns

- Referencing `CLAUDE.md` or `.cursorrules` by name in a shared instruction file. The check detects agent-specific filenames in shared files. Agent-specific content belongs in its own file.
- Mentioning `.clinerules` or `copilot-instructions.md` in a file that all agents read. Even factual references to agent-specific filenames violate neutrality in shared instructions.
- Writing agent-neutral prose but including an example that names a specific agent file. The check matches the filename pattern regardless of surrounding context.

## Pass / Fail

### Pass

~~~~markdown
# Coding Standards

Use `ruff` for formatting.
Run `pytest tests/` before committing.
Keep modules under 500 lines.
~~~~

### Fail

~~~~markdown
# Coding Standards

See `.cursorrules` for Cursor-specific settings.
Claude users should check `CLAUDE.md` for details.
~~~~

## Limitations

Checks for agent-specific filenames (CLAUDE.md, .cursorrules, copilot-instructions.md) referenced in content. Does not detect agent-specific terminology or conventions that don't mention filenames.

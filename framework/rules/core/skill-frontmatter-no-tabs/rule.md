---
id: CORE:S:0063
slug: skill-frontmatter-no-tabs
title: Skill Frontmatter No Tabs
category: structure
type: mechanical
severity: high
backed_by: []
match: {type: skills, format: [frontmatter, freeform]}
source: https://docs.nvidia.com/skills/skillevaluator/tier1-reference.md
---

# Skill Frontmatter No Tabs

A skill's frontmatter must be indented with spaces, never tabs. YAML does not allow tab indentation, and Codex and Copilot CLI fail to parse the block, so the skill does not load there.

The check reports a skill file with a frontmatter line that starts with a tab, or with spaces followed by a tab.

## Antipatterns

- Indenting a `metadata:` child or a folded description with a tab from an editor set to hard tabs.

## Pass / Fail

### Pass

~~~~yaml
---
name: example
description: Space indented.
metadata:
  author: me
---
~~~~

### Fail

~~~~yaml
---
name: example
description: Tab indented.
metadata:
	author: me
---
~~~~

## Limitations

Looks only at the start of each frontmatter line. A tab in the middle of a line, and tabs in the markdown body, are not reported. A block that does not read as YAML for another reason is reported by `skill-description-present`.

---
id: CORE:C:0037
slug: static-before-dynamic
title: "Stable Content First"
category: coherence
type: deterministic
severity: medium
match: {format: freeform}
---

# Stable Content First

Separate stable instructions from frequently-changing content using distinct sections. Stable content (identity, tool names, permanent constraints) should come first. Dynamic content (session-specific guidance, mutable configuration) should come later. The last positions in a file carry the strongest attention weight — placing dynamic content toward the end means updates land in high-attention positions without disrupting stable instructions above.

## Antipatterns

- **Flat file with no sections.** All instructions in one continuous block with no headings. Stable identity declarations sit next to mutable session guidance with no visual or structural separation.
- **Dynamic content at the top.** Placing TODO items, version-specific workarounds, or session notes at the beginning of the file, pushing stable identity and convention declarations below the fold.
- **Single heading for everything.** Using `# Project` as the only heading with all content underneath. The agent cannot distinguish stable from dynamic content.

## Pass / Fail

### Pass

```markdown
# Project Identity
This is a TypeScript API server using Express.

# Conventions
Use `prettier` for formatting.

# Current Sprint
Working on auth migration — see PR #42.
```

### Fail

```markdown
# Project
Working on auth migration.
This is a TypeScript API server using Express.
Use prettier for formatting.
```

## Limitations

Checks that the file uses 2 or more headings to separate content into layers. Does not verify whether the layers follow a stable-to-dynamic order — only that heading structure exists for organizing content.

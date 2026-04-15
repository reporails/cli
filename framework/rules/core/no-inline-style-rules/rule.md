---
id: CORE:C:0017
slug: no-inline-style-rules
title: "No Inline Style Rules"
category: coherence
type: deterministic
severity: high
backed_by: []
match: {format: freeform}
---

# No Inline Style Rules

Instruction files must not use agent-specific rendering directives like inline styles or scripts.

## Antipatterns

- Adding `<style>` blocks to control how an instruction file renders in a preview tool -- the check flags `<style` tags as forbidden content.
- Using `style="color:red"` on an HTML element to highlight a warning -- the check detects inline `style=` attributes.
- Embedding `<script>` tags for interactive examples -- the check flags `<script` as a rendering directive that does not belong in instruction files.
- Adding `class="highlight"` attributes to HTML elements -- the check also flags `class=` attributes as rendering directives.

## Pass / Fail

### Pass

~~~~markdown
## Constraints

*Do NOT modify files in `dist/`.* Use `ruff` for all formatting.
Run `uv run ails check .` after changes.
~~~~

### Fail

~~~~markdown
<style>h2 { color: red; }</style>

## Constraints

<p style="font-weight:bold">Do NOT modify files in dist.</p>
<script>console.log("loaded")</script>
~~~~

## Limitations

Detects inline HTML style and script elements. Does not evaluate CSS class references or external stylesheets.

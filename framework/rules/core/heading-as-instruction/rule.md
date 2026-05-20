---
id: CORE:S:0039
slug: heading-as-instruction
title: "Heading As Instruction"
category: structure
type: mechanical
severity: medium
match: {format: freeform}
fix: |
  Rewrite the heading as a topic label (the noun phrase the section is
  about). Move the directive verb into the section body. `## Always Run
  Tests` → `## Tests` with body `Run tests via \`pytest tests/\` before
  each commit.` Headings are structural anchors, not instructions.
---

# Heading As Instruction

Headings should organize content into sections, not carry instructions. The model processes heading content the same as body content, but instructions in headings are structurally fragile — they get lost when files are reorganized, and they can't carry the detail an instruction needs.

## Antipatterns

- **Imperative verb in a heading**: `## Always Run Tests Before Pushing` — this is an instruction disguised as a section label. The check classifies it as a charged heading atom (directive/imperative).
- **Constraint as heading**: `## Never Modify Generated Files` — constraints belong in the section body, not the heading. The heading should name the topic (e.g., `## Generated Files`).
- **Multi-clause heading**: `## Use ruff and Do Not Run black` — packing both a directive and a constraint into a heading makes both structurally fragile and undetectable by checks that scan body content.

## Pass / Fail

### Pass

~~~~markdown
## Deployment

Never push directly to main. Use feature branches and open a pull request.
~~~~

### Fail

~~~~markdown
## Never Push Directly to Main

Use feature branches and open a pull request instead.
~~~~

## Fix

Use the heading as a section label and put the instruction in the first line of the section body. For example, change `## Never push to main` to `## Deployment` with "Never push directly to main" as the first line under it.

## Limitations

Detects headings classified as directive, imperative, or constraint. Short headings with common verbs may be false positives — "## Process" is a label, not an instruction, but contains a verb.

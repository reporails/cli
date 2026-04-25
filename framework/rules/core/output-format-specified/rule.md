---
id: CORE:C:0025
slug: output-format-specified
title: Output Format Specified
category: coherence
type: mechanical
severity: high
backed_by: [agent-readmes-empirical-study, claude-code-issue-13579, developer-context-cursor-study,
  fowler-pushing-ai-autonomy, prompthub-cursor-rules-analysis]
match: {type: main}
---
# Output Format Specified

Instruction files must contain a heading referencing Output, Format, or Display. Specifying expected output formats tells the agent what shape its responses should take.

## Antipatterns

- Describing output expectations in body text under a generic heading like "## Usage" -- the check requires the heading itself to contain "Output", "Format", or "Display".
- Specifying "return JSON" in a bullet list but under a heading that does not mention format -- the heading-match check scans section headers, not list items.
- Relying on the agent to infer output format from examples alone without a dedicated heading -- implicit expectations are not detected by the heading check.

## Pass / Fail

### Pass

~~~~markdown
## Output Format

Return results as JSON with `status` and `message` fields.
Use markdown tables for multi-row output.
~~~~

### Fail

~~~~markdown
## Commands

- `ails check .` validates the project
- Results include rule violations and scores
~~~~

## Limitations

Checks for a heading containing "Output", "Format", or "Display". Does not verify the section specifies concrete format requirements.

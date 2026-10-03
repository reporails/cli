---
id: CORE:C:0059
slug: ambiguous-phrasing
title: "Ambiguous Phrasing"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
surface_mutations:
  memory: {applies: false}
---

# Ambiguous Phrasing

A sentence that uses instruction-shaped words — "never", "must", "always", "use" — but is written as a description of a fact or a requirement, rather than a command to the agent, does not get treated as an instruction. The agent reads it as background, not as something to follow, so it has no effect on behavior even though it looks like it should.

The same finding also covers a related case: reasoning text placed near a prohibition that names the very thing the prohibition forbids. Naming the forbidden thing in the reasoning can prime the agent toward it instead of reinforcing the prohibition.

## Antipatterns

- **A requirement written about the system, not to the agent**: `"FR-1: The system must allow users to reset their password."` Framed as a spec line describing what the system does, not a command telling the agent what to do right now.
- **A fact stated in passing that happens to use instruction-shaped words**: "Acceptance criteria must be verifiable, not vague." Read as a description of what good acceptance criteria look like, not an instruction to the agent.
- **Reasoning that names the forbidden thing**: "*Never run migrations directly against production.* Running a migration by hand against production has caused outages before." The second sentence repeats the forbidden action right next to the prohibition, working against it instead of backing it up.

## Pass / Fail

### Pass

~~~~markdown
## Requirements

Validate the reset-password form before submitting it.
Reject a request when the email field is empty.
~~~~

### Fail

~~~~markdown
## Requirements

Numbered list of specific functionalities:
- "FR-1: The system must allow users to reset their password."
- "FR-2: When a user clicks submit, the system must validate the form."
~~~~

## Limitations

Fires only on a sentence that does not read clearly as a command yet still carries instruction-shaped wording. A sentence written clearly enough to read as a command either way is not flagged, even if it also reads like a description. Rephrasing as a genuine instruction, or moving the sentence to a description section, both resolve it — the check cannot tell which the file needs.

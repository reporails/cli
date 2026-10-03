---
id: CORE:C:0060
slug: broad-conditional-scope
title: "Broad Conditional Scope"
category: coherence
type: mechanical
execution: server
severity: medium
match: {}
surface_mutations:
  memory: {applies: false}
---

# Broad Conditional Scope

An instruction that opens with a condition ("When...", "If...", "Unless...", "Before...", "After...") should name the specific situation it applies to. A condition that names outside systems — "external", "third-party", "service(s)", "integration(s)", "dependency" / "dependencies", "database", "SQL" — covers far more ground than the instruction's author likely intended, so the agent applies the instruction in situations no one checked. Wide but harmless wording such as "any file" or "all tests" is not reported.

## Antipatterns

- **A catch-all condition**: "When any external service fails, retry the request up to 3 times." "any external service" reaches every call the project makes, not just the one the author had in mind.
- **A vague dependency reference**: "If all dependencies are unavailable, fall back to cached data." "all dependencies" names no specific dependency, so the agent cannot tell which unavailability should trigger the fallback.
- **A broad integration condition**: "Before calling any third-party integration, log the request payload." Logging every outbound call to every integration is a much bigger behavior change than a narrowly-scoped instruction would produce.

## Pass / Fail

### Pass

~~~~markdown
# Retries

When the `payment-gateway` call times out, retry the request up to 3 times.
~~~~

### Fail

~~~~markdown
# Retries

When any external service fails, retry the request up to 3 times.
~~~~

## Limitations

Fires only on a conditional clause that contains one of the words listed above (whole words, singular or plural where one exists), in an instruction the file gives as a directive or a prohibition. A condition that avoids those words but is still vague in other ways ("under bad conditions") is not detected, and a condition naming a specific service or file by name never fires even when the underlying behavior is still broad.

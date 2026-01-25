---
paths: ["src/reporails_cli/bundled/**"]
---

# Bundled Config Files

NEVER modify bundled config files without explicit human instruction.

- `levels.yml` — Level definitions and rule-to-level mapping
- `capability-patterns.yml` — OpenGrep patterns for capability detection

These are CLI-owned orchestration logic, not framework rules.
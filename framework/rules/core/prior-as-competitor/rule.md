---
id: CORE:C:0052
slug: prior-as-competitor
title: "Default Behavior Competition"
category: coherence
type: mechanical
execution: server
severity: high
match: {}
---

# Default Behavior Competition

The model always has a default behavior for any task — what it does without instructions. When instructions conflict or are too weak, the model reverts to this default completely. The default is an ever-present competitor.

## Antipatterns

- **Hedged instructions opposing the default.** Writing "you might want to use `ruff` instead of `black`" when the model defaults to `black` will not override the default. Hedged modality produces zero behavioral change.
- **Conflicting instructions expecting a compromise.** Two instructions that disagree ("use tabs" vs "use spaces") do not produce a blend. The model reverts to its default (typically spaces), identical to no instruction at all.
- **Abstract instructions against specific defaults.** Writing "format code consistently" when the model already has a specific default formatter changes nothing. The instruction must name the exact tool and behavior to displace the default.

## Pass / Fail

### Pass

~~~~markdown
# Formatting

Use `ruff` for all formatting. Run `ruff format .` before committing.
*Never run a formatter other than `ruff`.*
~~~~

### Fail

~~~~markdown
# Formatting

Consider using a consistent code formatter.
You might want to format code before committing.
~~~~

## Limitations

This is an informational diagnostic. The model's default behavior for a given task cannot be directly measured — this rule flags instructions that are likely too weak to override defaults based on their specificity and modality. It fires once per topic whose every instruction is both vague and hedged, on the topic's first instruction; one named or direct instruction on the topic clears it, though an instruction written as a heading does not.

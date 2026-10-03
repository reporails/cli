---
id: CORE:C:0047
slug: position-recency
title: "Position Recency"
category: coherence
type: mechanical
execution: server
severity: low
match: {}
---

# Position Recency

A prohibition that names exactly what it forbids, placed early among instructions on unrelated subjects, is easily lost: the instructions after it outweigh it, and naming the forbidden thing draws attention to it rather than protecting the constraint.

## Antipatterns

- **A named prohibition ahead of unrelated instructions.** ``*NEVER modify `.env` files directly.*`` at the top of a file whose other instructions cover setup and testing is outweighed by everything after it.
- **No directive on the same subject.** The file forbids touching `.env` files but never says how environment configuration is handled, so nothing pairs with the constraint.

## Pass / Fail

### Pass

~~~~markdown
# Constraints

Load environment values from `.env.example` and the deploy pipeline's secret store.
*Never modify `.env` files directly.*
~~~~

### Fail

~~~~markdown
# Constraints

*NEVER modify `.env` files directly.*

# Project Setup

Use `uv sync` to install dependencies.
Run `uv run poe qa` for testing.
~~~~

## Limitations

Fires only on a prohibition that names what it forbids, sits early among instructions on unrelated subjects, and has no directive on the same subject in the file. An abstract or unnamed instruction, a directive, or a prohibition that follows a directive on its subject does not fire, wherever it sits. A directive on the same subject worded very differently from the prohibition may not be recognized as its match, so a genuinely related instruction elsewhere in the file can still be missed.

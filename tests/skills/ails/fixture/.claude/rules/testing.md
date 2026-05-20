---
description: testing convention
---

# Testing

Tests live in `tests/`. Run `uv run pytest tests/` to execute the unit suite. Add a test file for every new module in `src/` that introduces behavior beyond pure data shapes.

*Do not commit code without a passing test run.*

## Pass / Fail

### Pass

```
$ uv run pytest tests/unit/ -q
.................... [100%]
20 passed in 0.5s
```

### Fail

```
$ uv run pytest tests/unit/ -q
F.................
FAILED tests/unit/test_foo.py::test_bar
```

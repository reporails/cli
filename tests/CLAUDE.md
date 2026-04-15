# Tests

Unit and integration tests for `reporails` CLI.

- Add unit tests in `tests/unit/` for new functions in `src/reporails_cli/`
- Add integration tests in `tests/integration/` for changes to `src/reporails_cli/core/pipeline.py` or `src/reporails_cli/core/rule_runner.py`
- Read existing `test_*.py` files fully before adding new ones — duplicate tests waste CI time
- **Do not modify golden fixtures in `tests/fixtures/golden/`.* Update the corresponding expected output file alongside instead.*
- When requirements are ambiguous, ask for clarification rather than guessing test behavior

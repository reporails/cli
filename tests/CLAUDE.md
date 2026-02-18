# Tests

Unit and integration tests for reporails CLI.

- Add unit tests in `unit/` for new functions
- Add integration tests in `integration/` for pipeline changes
- Read existing tests fully before adding new ones to avoid duplication
- Reference from memory instead of re-reading unchanged fixtures
- When requirements are ambiguous, ask for clarification rather than guessing
- Do not modify golden fixtures; update the corresponding expected output alongside instead

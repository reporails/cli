# API Module Rules

These rules extend the root instructions for files under `src/api/`.

- Return typed response models from every handler; never a bare dict.
- Validate request bodies with the shared `RequestSchema` base class.
- Log every 5xx with the request id so traces stay joinable.

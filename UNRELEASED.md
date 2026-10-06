# Unreleased

### Added

### Changed

- Sign-in hints, `ails --help`, the npm wrapper's help and the docs point to `ails login` and `ails logout`. For CI and the GitHub Action, create an API key on reporails.com/account and set it as `AILS_API_KEY`.

### Fixed

### Removed

### Internal

- The stored sign-in is read through one reader, and messages from the server are read off a reply and remembered once shown.

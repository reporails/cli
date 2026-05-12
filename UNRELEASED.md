# Unreleased

### Added
- auth: Typed `PlatformUnavailableError` raised when `/api/auth/client-id` returns a non-JSON body, replacing the silent fall-through that surfaced as a misleading "OAuth not configured" message.

### Changed
- auth: Set explicit `User-Agent: reporails-cli/<version> (auth)` header on platform and GitHub requests so identifiable CLI traffic can be allow-listed at the edge.

### Fixed

### Removed

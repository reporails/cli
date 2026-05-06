# Unreleased

### Added

- [core/payload]: New `core/payload.py` module producing a compact msgpack-encoded wire payload with a leading version byte. Drops client-only diagnostic fields, packs binary embeddings as raw bytes (no base64 inflation), and replaces inline-token term lists with per-style counts. Real-data shrink 1.9–2.9× vs the legacy JSON path on monorepo-class fixtures (activepieces 1.9 MB → 1.0 MB), comfortably under the 2 MB anonymous tier byte cap.
- [core/funnel]: `WIRE_MAX_BYTES_BY_TIER` and `preflight_byte_size()` mirror the per-tier body cap so the CLI returns a clean local `payload_too_large` `FunnelError` before transmission instead of an opaque server-side 413.

### Changed

- [core/api_client]: `_lint_remote` now sends the compact wire format by default. Backend retains support for the legacy JSON path.

### Fixed

### Removed

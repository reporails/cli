# Unreleased

### Added

### Changed

- Build: bundle the `en_core_web_sm` spaCy pipeline (~15 MB) inside the wheel under `bundled/spacy/`, alongside the existing bundled ONNX embedder. `core/mapper/models.py` now loads the model by local filesystem path via `get_spacy_model_path()`. Replaces the prior URL-pinned runtime dep that blocked PyPI publication (`Requires-Dist: foo @ https://…` is rejected on upload).

### Fixed

### Removed

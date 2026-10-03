"""Mutation-closing behavioral tests for api_client.py.

Each test reddens when a specific operator mutation is reintroduced into the
source (verified with scripts/mutation_probe.py). Scope is LOCAL behavior:
the pure serialize/deserialize helpers and the client's fallback wiring.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.api_client import (
    AilsClient,
    _deserialize_cross_file,
    _deserialize_per_file,
    _deserialize_quality,
)

# --- L517: per_file diagnostic required-field guard (or -> and, 3 sites) ---


def _per_file_payload(diag: dict) -> dict:
    return {"per_file": [{"file": "a.md", "diagnostics": [diag]}]}


_COMPLETE_DIAG = {"line": 5, "severity": "error", "rule": "R1", "message": "boom"}


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("missing", ["line", "severity", "rule", "message"])
def test_diagnostic_missing_one_required_field_is_dropped(missing):
    """A diagnostic missing ANY one required field must be skipped.

    With the guard's `or` flipped to `and`, an entry missing a single field
    is retained; asserting zero diagnostics reddens each `or` site.
    """
    diag = dict(_COMPLETE_DIAG)
    del diag[missing]
    result = _deserialize_per_file(_per_file_payload(diag))
    assert len(result) == 1
    assert result[0].diagnostics == ()


@pytest.mark.unit
@pytest.mark.subsys_api
def test_complete_diagnostic_is_kept():
    result = _deserialize_per_file(_per_file_payload(dict(_COMPLETE_DIAG)))
    assert len(result[0].diagnostics) == 1


# --- L554: cross_file required-field guard (`is None` -> `is not None`) ---


_COMPLETE_CF = {
    "file_1": "a.md",
    "file_2": "b.md",
    "line_1": 1,
    "line_2": 2,
    "finding_type": "conflict",
}


@pytest.mark.unit
@pytest.mark.subsys_api
def test_complete_cross_file_entry_is_kept():
    """A complete cross_file entry must be retained.

    With `is None` flipped to `is not None`, a complete entry (no None values)
    is skipped, dropping it — asserting it is kept reddens the mutant.
    """
    result = _deserialize_cross_file({"cross_file": [dict(_COMPLETE_CF)]})
    assert len(result) == 1
    assert result[0].file_1 == "a.md"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_incomplete_cross_file_entry_is_dropped():
    entry = dict(_COMPLETE_CF)
    del entry["finding_type"]
    result = _deserialize_cross_file({"cross_file": [entry]})
    assert result == ()


@pytest.mark.unit
@pytest.mark.subsys_api
def test_explicit_null_display_score_deserializes_to_none():
    """An explicit `display_score: null` (unscored project) must deserialize to
    `None`, not the 0.0 used only when the key is absent entirely — `dict.get`
    only falls back to its default on a MISSING key, so a present `null` already
    passes through as `None`; this pins that the field's type also allows it.
    """
    result = _deserialize_quality({"quality": {"display_score": None}})
    assert result is not None
    assert result.display_score is None


@pytest.mark.unit
@pytest.mark.subsys_api
def test_missing_display_score_key_defaults_to_none():
    """A whole-project reply with no `display_score` key is unscored (`None`),
    matching the per-file convention — never rendered as `0.0/10`."""
    result = _deserialize_quality({"quality": {}})
    assert result is not None
    assert result.display_score is None


@pytest.mark.unit
@pytest.mark.subsys_api
def test_reply_without_quality_object_has_no_quality():
    assert _deserialize_quality({}) is None


# --- lint() forwards the local entries unchanged ---


@pytest.mark.unit
@pytest.mark.subsys_api
def test_lint_default_local_forwarded_as_empty(monkeypatch):
    """lint() with no local entries forwards an empty sequence to _lint_remote."""
    captured = {}

    def _fake_remote(self, ruleset_map, local, structural_required, root):
        captured["local"] = local
        return object()

    monkeypatch.setattr(AilsClient, "_lint_remote", _fake_remote, raising=True)
    client = AilsClient(base_url="https://example.invalid")
    client.lint(_make_map(), root=Path("/tmp/reporails-test-scan-root"))
    assert list(captured["local"]) == []


# --- L276: tier fallback chain (`tier or env or ... or "free"`, or -> and) ---


@pytest.mark.unit
@pytest.mark.subsys_api
def test_explicit_tier_wins_over_env(monkeypatch):
    """An explicit tier arg must win; the `or` chain short-circuits to it.

    With env set to a different value, `tier or env` -> tier, but the
    `or -> and` mutant yields env — asserting the explicit tier reddens it.
    """
    monkeypatch.setenv("AILS_TIER", "enterprise")
    client = AilsClient(base_url="https://example.invalid", tier="pro")
    assert client.tier == "pro"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_env_tier_used_when_no_explicit_tier(monkeypatch):
    """With no explicit tier, the env value is used (second `or` site)."""
    monkeypatch.setenv("AILS_TIER", "enterprise")
    client = AilsClient(base_url="https://example.invalid")
    assert client.tier == "enterprise"


def _make_map():
    from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary

    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )

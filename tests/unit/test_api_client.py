"""Tests for core/api_client.py — diagnostic API client."""

from __future__ import annotations

from reporails_cli.core.api_client import (
    AilsClient,
    LintResult,
    _deserialize_cross_file_coordinates,
    _deserialize_hints,
    _deserialize_lint_result,
    _strip_and_serialize,
)
from reporails_cli.core.funnel import (
    UNIVERSAL_ATOM_CAP,
    WIRE_MAX_CLUSTERS,
    WIRE_MAX_FILES,
    LintResponse,
    preflight_oversized,
)
from reporails_cli.core.mapper.mapper import Atom, FileRecord, RulesetMap, RulesetSummary


def _make_map() -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )


class TestAilsClient:
    def test_lint_empty_response_without_server(self) -> None:
        """No local fallback — lint requires the API."""
        client = AilsClient(base_url="")
        response = client.lint(_make_map())
        assert isinstance(response, LintResponse)
        assert response.result is None
        assert response.funnel_error is None

    def test_lint_empty_response_on_unreachable_server(self) -> None:
        client = AilsClient(base_url="https://localhost:1")
        response = client.lint(_make_map())
        assert isinstance(response, LintResponse)
        assert response.result is None

    def test_custom_base_url(self) -> None:
        client = AilsClient(base_url="https://custom.example.com")
        assert client.base_url == "https://custom.example.com"


class TestV2WireFormat:
    """Verify _strip_and_serialize emits v2 obfuscated wire format."""

    @staticmethod
    def _make_atom(**overrides: object) -> Atom:
        """Build a minimal Atom with defaults."""
        defaults: dict[str, object] = {
            "line": 1,
            "text": "",
            "kind": "excitation",
            "charge": "NEUTRAL",
            "charge_value": 0,
            "modality": "none",
            "specificity": "abstract",
        }
        defaults.update(overrides)
        return Atom(**defaults)  # type: ignore[arg-type]

    @staticmethod
    def _make_rm(files: tuple[FileRecord, ...], atoms: tuple[Atom, ...]) -> RulesetMap:
        return RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=files,
            atoms=atoms,
            summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=len(atoms)),
        )

    def test_schema_version_bumped(self) -> None:
        rm = self._make_rm((), ())
        assert _strip_and_serialize(rm)["schema_version"] == "2"

    def test_semantic_keys_absent(self) -> None:
        """No semantic field names in serialized atoms."""
        fr = FileRecord(path="test.md", content_hash="a")
        atom = self._make_atom(file_path="test.md")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        semantic = {
            "charge",
            "modality",
            "specificity",
            "format",
            "kind",
            "file_path",
            "cluster_id",
            "position_index",
            "token_count",
            "scope_conditional",
            "embedding_b64",
            "heading_context",
            "depth",
            "ambiguous",
            "embedded_charge_markers",
            "inline",
        }
        assert not semantic & set(a.keys()), f"Semantic keys leaked: {semantic & set(a.keys())}"

    def test_short_keys_present(self) -> None:
        """All required short keys emitted."""
        fr = FileRecord(path="test.md", content_hash="a")
        atom = self._make_atom(file_path="test.md")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        required = {"line", "t", "c", "cv", "m", "s", "sc", "f", "pi", "tc", "fi", "k"}
        assert required <= set(a.keys()), f"Missing keys: {required - set(a.keys())}"

    def test_enum_fields_are_integers(self) -> None:
        """Enum fields serialized as integers, not strings."""
        fr = FileRecord(path="test.md", content_hash="a")
        atom = self._make_atom(file_path="test.md")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        for key in ("t", "c", "m", "s", "f"):
            assert isinstance(a[key], int), f"{key} should be int, got {type(a[key])}"

    def test_file_index_reference(self) -> None:
        f1 = FileRecord(path="CLAUDE.md", content_hash="a")
        f2 = FileRecord(path=".claude/rules/test.md", content_hash="b")
        a1 = self._make_atom(file_path="CLAUDE.md")
        a2 = self._make_atom(file_path=".claude/rules/test.md")
        payload = _strip_and_serialize(self._make_rm((f1, f2), (a1, a2)))
        assert payload["atoms"][0]["fi"] == 0
        assert payload["atoms"][1]["fi"] == 1

    def test_inline_style_integer_codes(self) -> None:
        atom = self._make_atom(
            named_tokens=["ruff"],
            italic_tokens=["always"],
            bold_tokens=["NEVER"],
        )
        fr = FileRecord(path="test.md", content_hash="a")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        assert "il" in a
        styles = [span["s"] for span in a["il"]]
        assert all(isinstance(s, int) for s in styles)
        assert len(a["il"]) == 3
        # Each span has term + integer style code
        terms = [span["term"] for span in a["il"]]
        assert terms == ["ruff", "always", "NEVER"]

    def test_text_fields_stripped(self) -> None:
        atom = self._make_atom(
            text="sensitive content",
            plain_text="stripped",
            rule="p1_negation",
            role="constraint",
            topics=("security",),
        )
        fr = FileRecord(path="test.md", content_hash="a")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        for key in ("text", "plain_text", "rule", "role", "topics"):
            assert key not in a, f"Sensitive field '{key}' leaked into wire format"

    def test_optional_fields_omitted_when_empty(self) -> None:
        atom = self._make_atom()
        fr = FileRecord(path="test.md", content_hash="a")
        a = _strip_and_serialize(self._make_rm((fr,), (atom,)))["atoms"][0]
        # Optional fields not present when default/empty
        for key in ("il", "e", "hc", "d", "a", "ecm"):
            assert key not in a, f"Optional field '{key}' present when it should be absent"


class TestPayloadCaps:
    """Preflight rejects oversized payloads before the HTTP round-trip."""

    def test_within_caps_returns_none(self) -> None:
        assert preflight_oversized({"files": [], "atoms": [], "clusters": []}, has_api_key=True) is None

    def test_files_over_cap(self) -> None:
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": [], "clusters": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "payload_too_large"
        assert err.limit == WIRE_MAX_FILES

    def test_atoms_over_cap(self) -> None:
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1), "clusters": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "atom_cap_exceeded"
        assert err.limit == UNIVERSAL_ATOM_CAP

    def test_clusters_over_cap(self) -> None:
        payload = {"files": [], "atoms": [], "clusters": [{}] * (WIRE_MAX_CLUSTERS + 1)}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "payload_too_large"
        assert err.limit == WIRE_MAX_CLUSTERS

    def test_at_cap_boundary_passes(self) -> None:
        payload = {
            "files": [{}] * WIRE_MAX_FILES,
            "atoms": [{}] * UNIVERSAL_ATOM_CAP,
            "clusters": [{}] * WIRE_MAX_CLUSTERS,
        }
        assert preflight_oversized(payload, has_api_key=True) is None

    def test_lint_skips_http_when_over_cap(self) -> None:
        """Oversized payload short-circuits before any network call."""
        from unittest.mock import patch

        from reporails_cli.core.mapper.mapper import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        oversized = {
            "schema_version": "2",
            "embedding_model": "test",
            "generated_at": "2026-01-01T00:00:00Z",
            "files": [{}],  # one file so the empty-payload guard doesn't fire first
            "atoms": [],
            "clusters": [{}] * (WIRE_MAX_CLUSTERS + 1),
            "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0, "n_topics": 0, "n_topics_charged": 0},
        }
        with (
            patch("reporails_cli.core.api_client._strip_and_serialize", return_value=oversized),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(rm)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "payload_too_large"
        mock_post.assert_not_called()

    def test_lint_skips_http_when_no_files(self) -> None:
        """Empty-files payload short-circuits — Worker would 400 missing_content_hash."""
        from unittest.mock import patch

        from reporails_cli.core.mapper.mapper import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        empty_payload = {
            "schema_version": "2",
            "embedding_model": "test",
            "generated_at": "2026-01-01T00:00:00Z",
            "files": [],
            "atoms": [],
            "clusters": [],
            "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0, "n_topics": 0, "n_topics_charged": 0},
        }
        with (
            patch("reporails_cli.core.api_client._strip_and_serialize", return_value=empty_payload),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(rm)
        assert response.result is None
        assert response.funnel_error is None
        mock_post.assert_not_called()


class TestDeserializeHints:
    def test_valid_hints(self) -> None:
        data = {
            "hints": [
                {
                    "file": "CLAUDE.md",
                    "diagnostic_type": "CORE:C:0044",
                    "count": 3,
                    "summary": "3 topics",
                    "severity": "error",
                    "error_count": 2,
                    "warning_count": 1,
                },
            ]
        }
        hints = _deserialize_hints(data)
        assert len(hints) == 1
        assert hints[0].file == "CLAUDE.md"
        assert hints[0].error_count == 2
        assert hints[0].severity == "error"

    def test_missing_fields_skipped(self) -> None:
        hints = _deserialize_hints({"hints": [{"file": "x.md"}]})
        assert len(hints) == 0

    def test_empty(self) -> None:
        assert _deserialize_hints({}) == ()
        assert _deserialize_hints({"hints": []}) == ()


class TestDeserializeCrossFileCoordinates:
    def test_valid_coordinates(self) -> None:
        data = {
            "cross_file_coordinates": [
                {"file_1": "a.md", "file_2": "b.md", "finding_type": "conflict", "count": 2},
                {"file_1": "c.md", "file_2": "d.md", "finding_type": "repetition", "count": 1},
            ]
        }
        coords = _deserialize_cross_file_coordinates(data)
        assert len(coords) == 2
        assert coords[0].finding_type == "conflict"
        assert coords[0].count == 2

    def test_missing_fields_skipped(self) -> None:
        coords = _deserialize_cross_file_coordinates({"cross_file_coordinates": [{"file_1": "a.md"}]})
        assert len(coords) == 0

    def test_empty(self) -> None:
        assert _deserialize_cross_file_coordinates({}) == ()


class TestDeserializeLintResult:
    def test_full_response_with_coordinates(self) -> None:
        data = {
            "report": {"per_file": [], "cross_file": [], "quality": {"compliance_band": "HIGH"}, "stats": {}},
            "hints": [{"file": "CLAUDE.md", "diagnostic_type": "CORE:C:0044", "count": 3, "summary": "3 topics"}],
            "cross_file_coordinates": [
                {"file_1": "a.md", "file_2": "b.md", "finding_type": "conflict", "count": 1},
            ],
            "tier": "anonymous",
        }
        result = _deserialize_lint_result(data)
        assert isinstance(result, LintResult)
        assert result.tier == "anonymous"
        assert len(result.hints) == 1
        assert len(result.cross_file_coordinates) == 1

    def test_pro_tier_no_hints_or_coordinates(self) -> None:
        data = {"report": {"per_file": [], "cross_file": [], "quality": {}, "stats": {}}, "tier": "pro"}
        result = _deserialize_lint_result(data)
        assert result.tier == "pro"
        assert result.hints == ()
        assert result.cross_file_coordinates == ()

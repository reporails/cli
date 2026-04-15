"""Tests for core/api_client.py — diagnostic API client."""

from __future__ import annotations

from reporails_cli.core.api_client import AilsClient, LintResult, _strip_and_serialize
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
    def test_lint_returns_none_without_server(self) -> None:
        """No local fallback — lint requires the API."""
        client = AilsClient(base_url="")
        result = client.lint(_make_map())
        assert result is None

    def test_lint_returns_none_on_unreachable_server(self) -> None:
        client = AilsClient(base_url="https://localhost:1")
        result = client.lint(_make_map())
        assert result is None

    def test_custom_base_url(self) -> None:
        client = AilsClient(base_url="https://custom.example.com")
        assert client.base_url == "https://custom.example.com"


class TestV2WireFormat:
    """Verify _strip_and_serialize emits v2 obfuscated wire format."""

    @staticmethod
    def _make_atom(**overrides: object) -> Atom:
        """Build a minimal Atom with defaults."""
        defaults: dict[str, object] = dict(
            line=1, text="", kind="excitation", charge="NEUTRAL",
            charge_value=0, modality="none", specificity="abstract",
        )
        defaults.update(overrides)
        return Atom(**defaults)  # type: ignore[arg-type]

    @staticmethod
    def _make_rm(files: tuple[FileRecord, ...], atoms: tuple[Atom, ...]) -> RulesetMap:
        return RulesetMap(
            schema_version="1.0.0", embedding_model="test",
            generated_at="2026-01-01T00:00:00Z", files=files, atoms=atoms,
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
        semantic = {"charge", "modality", "specificity", "format", "kind",
                    "file_path", "cluster_id", "position_index", "token_count",
                    "scope_conditional", "embedding_b64", "heading_context",
                    "depth", "ambiguous", "embedded_charge_markers", "inline"}
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
            named_tokens=["ruff"], italic_tokens=["always"], bold_tokens=["NEVER"],
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
            text="sensitive content", plain_text="stripped",
            rule="p1_negation", role="constraint", topics=("security",),
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

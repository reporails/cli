"""Mutation-killing tests for the classify engine's pure internals.

Each test here earns its place by reddening when a real bug returns — the cases
were derived from a mutation sweep (`poe test_mutation`) of `classify/__init__.py`:
every assertion below kills a specific operator mutation that the prior suite let
survive. They demonstrate behavior (the function does the right thing at its
boundary), never decorate shape.

Killed survivors (module line → mutation):
  - L166  `spec.get("required", False)`        False→True
  - L223  `_is_loose_leaf_pattern` `**/` arm   True→False
  - L225  bare-leaf `and`                       and→or
  - L255  `scope == "global" and loading ...`   ==→!= (x2), and→or
  - L260  path-prefixed early return            True→False
  - L409  `match is None`                       is→is not
  - L434  `_prop_matches` list-vs-list guard    and→or
  - L446  `file_matches` type-mismatch return   False→True
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import (
    _is_loose_leaf_pattern,
    _location_matches_mode,
    _parse_file_types,
    resolve_match_to_paths,
)
from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch, FileTypeDeclaration
from reporails_cli.core.platform.policy.matching import _prop_matches, file_matches

# ═══════════════════════════════════════════════════════════════════════
# _is_loose_leaf_pattern — location-ambiguous glob detection (L223, L225)
# ═══════════════════════════════════════════════════════════════════════


class TestIsLooseLeafPattern:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    @pytest.mark.parametrize(
        "pattern, expected",
        [
            ("**/CLAUDE.md", True),  # kills L223 True→False (the `**/` arm)
            ("CLAUDE.md", True),  # bare leaf is loose
            ("AGENTS.md", True),
            (".github/copilot-instructions.md", False),  # kills L225 and→or (path prefix pins it)
            (".claude/rules/**/*.md", False),  # has both `/` and `**`
            ("docs/guide.md", False),
        ],
    )
    def test_loose_leaf_classification(self, pattern: str, expected: bool) -> None:
        """A pattern is loose only when it can match at any depth (`**/X` or bare `X`)."""
        assert _is_loose_leaf_pattern(pattern) is expected


# ═══════════════════════════════════════════════════════════════════════
# _location_matches_mode — eager/nested loading model (L255 x3, L260)
# ═══════════════════════════════════════════════════════════════════════


class TestLocationMatchesMode:
    @staticmethod
    def _ft(scope: str, loading: str) -> FileTypeDeclaration:
        return FileTypeDeclaration(
            name="main",
            patterns=("**/CLAUDE.md",),
            properties={"scope": scope, "loading": loading},
        )

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_global_session_start_loose_requires_ancestor_chain(self) -> None:
        """A global session_start file on a loose pattern matches only inside the chain."""
        root = Path("/proj")
        ft = self._ft("global", "session_start")
        # In-chain (file at root) → matches.
        assert _location_matches_mode(root / "CLAUDE.md", ft, {root}, "**/CLAUDE.md") is True
        # Out-of-chain (file in a descendant subdir) → does NOT match — kills L255 ==→!= (both).
        assert _location_matches_mode(root / "sub" / "CLAUDE.md", ft, {root}, "**/CLAUDE.md") is False

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_global_but_not_session_start_ignores_chain(self) -> None:
        """`and` — a global file that is NOT session_start skips the ancestor-chain gate.

        Kills L255 and→or: with `or`, this on-demand global would wrongly be gated to
        the chain and fail out-of-chain; correct behavior returns True anywhere.
        """
        ft = self._ft("global", "on_demand")
        root = Path("/proj")
        assert _location_matches_mode(root / "sub" / "CLAUDE.md", ft, {root}, "**/CLAUDE.md") is True

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_global_session_start_path_prefixed_skips_chain(self) -> None:
        """A path-prefixed pattern already pins location → matches regardless of chain.

        Kills L260 True→False (the early return for the non-loose pattern branch).
        """
        ft = self._ft("global", "session_start")
        root = Path("/proj")
        assert (
            _location_matches_mode(
                root / "sub" / ".github" / "copilot-instructions.md",
                ft,
                {root},
                ".github/copilot-instructions.md",
            )
            is True
        )

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_nested_scope_matches_only_outside_chain(self) -> None:
        """A nested file matches descendants (outside the chain), not files at cwd."""
        ft = FileTypeDeclaration(
            name="nested_context",
            patterns=("**/CLAUDE.md",),
            properties={"scope": "nested"},
        )
        root = Path("/proj")
        assert _location_matches_mode(root / "sub" / "CLAUDE.md", ft, {root}, "**/CLAUDE.md") is True
        assert _location_matches_mode(root / "CLAUDE.md", ft, {root}, "**/CLAUDE.md") is False


# ═══════════════════════════════════════════════════════════════════════
# _prop_matches / file_matches — property targeting (L434, L446)
# ═══════════════════════════════════════════════════════════════════════


class TestPropMatches:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_list_criterion_vs_scalar_actual_uses_membership_not_set_intersection(self) -> None:
        """match=list vs actual=str is a membership test, NOT a char-set intersection.

        Kills L434 and→or: with `or`, a list criterion against a scalar wrongly enters
        the `set(match_val) & set(actual)` branch, which compares CHARACTERS and misses
        a genuine multi-char membership hit.
        """
        assert _prop_matches(["ab", "cd"], "ab") is True  # "ab" ∈ ["ab", "cd"]
        assert _prop_matches(["ab", "cd"], "xy") is False

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_none_criterion_is_wildcard(self) -> None:
        assert _prop_matches(None, "anything") is True

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_file_type_mismatch_does_not_match(self) -> None:
        """A file whose type differs from the criterion does not match — kills L446 False→True."""
        cf = ClassifiedFile(path=Path("/proj/x.md"), file_type="skills", properties={})
        assert file_matches(cf, FileMatch(type="main")) is False
        assert file_matches(cf, FileMatch(type="skills")) is True


# ═══════════════════════════════════════════════════════════════════════
# resolve_match_to_paths — None-match wildcard (L409)
# ═══════════════════════════════════════════════════════════════════════


class TestResolveMatchToPaths:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_none_match_returns_all_paths(self) -> None:
        """match=None is the all-files wildcard — kills L409 is→is not (which inverts it)."""
        root = Path("/proj")
        classified = [
            ClassifiedFile(path=root / "a.md", file_type="main", properties={}),
            ClassifiedFile(path=root / "sub" / "b.md", file_type="skills", properties={}),
        ]
        assert resolve_match_to_paths(classified, None, root) == ["a.md", "sub/b.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_specific_match_filters(self) -> None:
        root = Path("/proj")
        classified = [
            ClassifiedFile(path=root / "a.md", file_type="main", properties={}),
            ClassifiedFile(path=root / "b.md", file_type="skills", properties={}),
        ]
        assert resolve_match_to_paths(classified, FileMatch(type="skills"), root) == ["b.md"]


# ═══════════════════════════════════════════════════════════════════════
# _parse_file_types — required defaults to False (L166)
# ═══════════════════════════════════════════════════════════════════════


class TestParseFileTypes:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_required_defaults_to_false_when_absent(self) -> None:
        """A file_type spec with no `required` key defaults to False — kills L166 False→True."""
        decls = _parse_file_types({"foo": {"patterns": ["**/FOO.md"]}})
        assert len(decls) == 1
        assert decls[0].required is False

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_required_honored_when_present(self) -> None:
        decls = _parse_file_types({"foo": {"patterns": ["**/FOO.md"], "required": True}})
        assert decls[0].required is True


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_the_verb_noun_determiners_extend_the_public_determiner_list() -> None:
    from reporails_cli.core.mapper import classify

    assert not hasattr(classify, "_DETERMINERS")
    assert classify.DETERMINERS < classify._VERB_NOUN_DETERMINERS

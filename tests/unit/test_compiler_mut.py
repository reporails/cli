"""Mutation-killing tests for core.lint.regex.compiler.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). See test_regex_engine.py for the adversarial suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reporails_cli.core.lint.regex.compiler import (
    CompiledCheck,
    _compile_pattern,
    _get_combinable_pattern,
    compile_rules,
)


def _write_regex_rule(tmp_path: Path) -> Path:
    p = tmp_path / "rule.yml"
    p.write_text(
        yaml.dump(
            {"checks": [{"id": "R1", "message": "m", "severity": "WARNING", "pattern-regex": "foo"}]},
            default_flow_style=False,
        )
    )
    return p


# ── body_only field default + set path (L32, L203) ───────────────────


class TestBodyOnlyFlag:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_body_only_defaults_false(self, tmp_path: Path) -> None:
        # Kills L32 `body_only = False -> True`: a rule not in body_only_paths
        # compiles to a check that matches the whole file.
        p = _write_regex_rule(tmp_path)
        result = compile_rules([p])
        assert len(result.checks) == 1
        assert result.checks[0].body_only is False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_body_only_set_when_path_flagged(self, tmp_path: Path) -> None:
        # Kills L203 `body_only=True -> False`: a rule whose yml is in
        # body_only_paths compiles to a body-only check.
        p = _write_regex_rule(tmp_path)
        result = compile_rules([p], body_only_paths={p})
        assert len(result.checks) == 1
        assert result.checks[0].body_only is True


# ── Combinable-pattern eligibility (L245, L246, L250) ────────────────


class TestGetCombinablePattern:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_mixed_positive_and_either_is_not_combinable(self) -> None:
        # A check carrying BOTH AND-patterns and either-patterns is not
        # embeddable and must return None.
        # Kills L245 `and -> or`: `or` would enter the AND-branch and emit a
        # pattern. Kills L250 `and -> or`: `or` would enter the either-branch.
        pat = _compile_pattern("foo")
        check = CompiledCheck(
            id="x",
            message="",
            severity="warning",
            patterns=(pat,),
            negative_patterns=(),
            either_patterns=(pat,),
            path_includes=(),
        )
        assert _get_combinable_pattern(check) is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_single_positive_pattern_is_combinable(self) -> None:
        # Kills L246 `== -> !=`: a lone AND-pattern (len == 1) is embeddable and
        # returns its pattern string; `!= 1` would reject it as None.
        pat = _compile_pattern("foo")
        check = CompiledCheck(
            id="x",
            message="",
            severity="warning",
            patterns=(pat,),
            negative_patterns=(),
            either_patterns=(),
            path_includes=(),
        )
        assert _get_combinable_pattern(check) == "foo"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_multiple_positive_patterns_not_combinable(self) -> None:
        # Reinforces L246 from the other side: two AND-patterns (len != 1) can't
        # be alternation-combined and must return None.
        check = CompiledCheck(
            id="x",
            message="",
            severity="warning",
            patterns=(_compile_pattern("foo"), _compile_pattern("bar")),
            negative_patterns=(),
            either_patterns=(),
            path_includes=(),
        )
        assert _get_combinable_pattern(check) is None

"""Mutation-closing tests for `core/classify/stopwords_sync.py`.

Each test pins a behavioral output (result.updated / result.skipped, the written
checks.yml content, or StalenessResult.stale) that a specific injected operator
mutation flips, so the test reddens the moment that bug returns. Derived from the
mutation probe over `stopwords_sync.py`; targets the sync-dispatch, targeted-field,
auto-detect, and staleness branches the existing suite left uncovered.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reporails_cli.core.classify.stopwords_sync import (
    check_staleness,
    sync_all,
    sync_vocab,
)


def _setup(rule_dir: Path, checks: list[dict], vocab: object) -> None:
    (rule_dir / "checks.yml").write_text(yaml.dump({"checks": checks}), encoding="utf-8")
    (rule_dir / "vocab.yml").write_text(yaml.dump(vocab), encoding="utf-8")


def _read_checks(rule_dir: Path) -> list[dict]:
    data = yaml.safe_load((rule_dir / "checks.yml").read_text(encoding="utf-8"))
    return data.get("checks", [])


# ── Targeted (dict vocab) sync — _sync_targeted ───────────────────────


class TestSyncTargeted:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_args_pattern_updates(self, tmp_path: Path) -> None:
        """dict vocab targeting args.pattern updates a mechanical check.

        Kills L85 `==`->`!=` (target guard) and L86 `or`->`and`
        (`check.get("args") or {}` would collapse to `{}`).
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.mc",
                    "type": "mechanical",
                    "check": "content_absent",
                    "args": {"pattern": "(?:a|b)"},
                }
            ],
            vocab={"mc": {"args.pattern": ["a", "b", "c"]}},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 1
        assert _read_checks(tmp_path)[0]["args"]["pattern"] == "(?:a|b|c)"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_mechanical_ctype_does_not_widen_to_other_targets(self, tmp_path: Path) -> None:
        """A non-args.pattern target on a mechanical check must not update args.

        Kills L85 `and`->`or`: with `or`, `ctype == "mechanical"` alone would
        route a `pattern-regex`-keyed term set into `args.pattern`.
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.mc",
                    "type": "mechanical",
                    "check": "content_absent",
                    "args": {"pattern": "(?:a|b)"},
                }
            ],
            vocab={"mc": {"pattern-regex": ["x", "y"]}},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert _read_checks(tmp_path)[0]["args"]["pattern"] == "(?:a|b)"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_targeted_no_op_reports_skipped(self, tmp_path: Path) -> None:
        """A targeted field that cannot decompose leaves updated at 0.

        Kills L90 `return False` (_sync_targeted fallthrough) and L108
        `changed = False` (_dispatch_sync dict accumulator) — either flipped
        would report a phantom update.
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.mc",
                    "type": "mechanical",
                    "check": "content_absent",
                    "args": {"pattern": "^---"},  # no alternation -> not decomposable
                }
            ],
            vocab={"mc": {"args.pattern": ["x"]}},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert result.skipped == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_pattern_regex_target_updates(self, tmp_path: Path) -> None:
        """dict vocab targeting pattern-regex updates a standalone deterministic check.

        Kills L92 `==`->`!=` (target guard).
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.d",
                    "type": "deterministic",
                    "pattern-regex": r"(?i)\b(?:a|b)\b",
                }
            ],
            vocab={"d": {"pattern-regex": ["a", "b", "c"]}},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 1
        assert _read_checks(tmp_path)[0]["pattern-regex"] == r"(?i)\b(?:a|b|c)\b"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_other_target_does_not_leak_into_pattern_regex(self, tmp_path: Path) -> None:
        """A pattern-not-regex target must not fall through to pattern-regex.

        Kills L92 `and`->`or`: with `or`, the presence of a top-level
        `pattern-regex` would let an unrelated target overwrite it.
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.d",
                    "type": "deterministic",
                    "pattern-regex": "(?:a|b)",
                }
            ],
            vocab={"d": {"pattern-not-regex": ["x", "y"]}},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert _read_checks(tmp_path)[0]["pattern-regex"] == "(?:a|b)"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_scalar_vocab_value_is_skipped(self, tmp_path: Path) -> None:
        """A scalar (non-list/non-dict) vocab value dispatches to no sync.

        Kills L113 `return False` (_dispatch_sync fallthrough).
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.d",
                    "type": "deterministic",
                    "pattern-regex": "(?:a|b)",
                }
            ],
            vocab={"d": "not a list or dict"},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert result.skipped == 1


# ── Flat (list vocab) sync — _sync_flat ───────────────────────────────


class TestSyncFlat:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_mechanical_non_decomposable_no_update(self, tmp_path: Path) -> None:
        """content_absent whose pattern cannot decompose reports no update.

        Kills L67 `return False` (mechanical branch fallthrough).
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.mc",
                    "type": "mechanical",
                    "check": "content_absent",
                    "args": {"pattern": "^---"},
                }
            ],
            vocab={"mc": ["x"]},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert result.skipped == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_non_deterministic_check_no_update(self, tmp_path: Path) -> None:
        """A semantic check is not a sync target — no update.

        Kills L70 `return False` (`ctype != "deterministic"` guard).
        """
        _setup(
            tmp_path,
            checks=[{"id": "X.0001.sem", "type": "semantic"}],
            vocab={"sem": ["a", "b"]},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert result.skipped == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_patterns_array_all_guards_no_update(self, tmp_path: Path) -> None:
        """A patterns array with only a guard entry yields no update.

        Kills L55 `return False` (_sync_patterns_array fallthrough).
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.kw",
                    "type": "deterministic",
                    "patterns": [{"pattern-regex": r"(?s)\A[\s\S]+"}],
                }
            ],
            vocab={"kw": ["a", "b"]},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert result.skipped == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_patterns_array_preferred_over_standalone(self, tmp_path: Path) -> None:
        """With both a non-decomposable pattern-regex and a patterns array,
        the array is the sync target.

        Kills L72 `and`->`or`: with `or`, a present top-level pattern-regex
        would short-circuit to the (failing) standalone branch.
        """
        _setup(
            tmp_path,
            checks=[
                {
                    "id": "X.0001.d",
                    "type": "deterministic",
                    "pattern-regex": "^---",  # non-decomposable, present but not the target
                    "patterns": [{"pattern-regex": "(?:a|b)"}],
                }
            ],
            vocab={"d": ["x", "y"]},
        )
        result = sync_vocab(tmp_path)
        assert result.updated == 1
        assert _read_checks(tmp_path)[0]["patterns"][0]["pattern-regex"] == "(?:x|y)"


# ── sync_vocab write gating + sync_all default ────────────────────────


class TestSyncWriteGating:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_write_when_nothing_modified(self, tmp_path: Path) -> None:
        """When terms already match, checks.yml is left byte-identical.

        Kills L160 `modified = False`: flipping it to True would rewrite
        (and reformat) the file despite no semantic change.
        """
        # Write checks.yml in flow style so a spurious rewrite (block style,
        # per the src dump args) is byte-detectable — a no-op sync must not touch it.
        (tmp_path / "checks.yml").write_text(
            yaml.dump(
                {"checks": [{"id": "X.0001.d", "type": "deterministic", "pattern-regex": "(?:a|b)"}]},
                default_flow_style=True,
            ),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": ["a", "b"]}), encoding="utf-8")
        before = (tmp_path / "checks.yml").read_bytes()
        result = sync_vocab(tmp_path)
        assert result.updated == 0
        assert (tmp_path / "checks.yml").read_bytes() == before

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sync_all_writes_by_default(self, tmp_path: Path) -> None:
        """sync_all defaults to a real (non-dry) run and persists changes.

        Kills L183 `dry_run: bool = False`: flipping the default to True
        would silently make sync_all never write.
        """
        rule_dir = tmp_path / "myrule"
        rule_dir.mkdir()
        _setup(
            rule_dir,
            checks=[
                {
                    "id": "X.0001.d",
                    "type": "deterministic",
                    "pattern-regex": "(?:a|b)",
                }
            ],
            vocab={"d": ["a", "b", "c"]},
        )
        results = sync_all(tmp_path)
        assert any(r.updated == 1 for r in results)
        assert _read_checks(rule_dir)[0]["pattern-regex"] == "(?:a|b|c)"


# ── check_staleness ───────────────────────────────────────────────────


class TestStaleness:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_parse_error_is_stale(self, tmp_path: Path) -> None:
        """Unparseable checks.yml is reported stale, not clean.

        Kills L265 `stale=True`->`False` (parse-error branch).
        """
        (tmp_path / "checks.yml").write_text("checks: [unclosed\n", encoding="utf-8")
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": ["a", "b"]}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is True
        assert "parse error" in result.stale_checks

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_non_mapping_vocab_is_stale(self, tmp_path: Path) -> None:
        """A vocab.yml that is a list (not a mapping) is invalid -> stale.

        Kills L267 `or`->`and`: with `and`, a non-dict vocab beside a valid
        checks_data would fall through to `.items()` on a list.
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump({"checks": [{"id": "X.0001.d", "type": "deterministic", "pattern-regex": "(?:a|b)"}]}),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump(["a", "b"]), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is True
        assert "invalid format" in result.stale_checks

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_auto_prefers_patterns_array(self, tmp_path: Path) -> None:
        """A list vocab (auto) reads terms from the patterns array, not a
        non-decomposable standalone pattern-regex.

        Kills L209 `and`->`or` in _auto_detect_terms.
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump(
                {
                    "checks": [
                        {
                            "id": "X.0001.d",
                            "type": "deterministic",
                            "pattern-regex": "^---",
                            "patterns": [{"pattern-regex": "(?:a|b)"}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": ["a", "b"]}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_args_pattern_target_matches(self, tmp_path: Path) -> None:
        """A dict vocab targeting args.pattern reads current mechanical terms.

        Kills L227 `==`->`!=` (args.pattern target guard in
        _extract_current_terms).
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump(
                {
                    "checks": [
                        {
                            "id": "X.0001.mc",
                            "type": "mechanical",
                            "check": "content_absent",
                            "args": {"pattern": "(?:a|b)"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"mc": {"args.pattern": ["a", "b"]}}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_pattern_regex_target_matches(self, tmp_path: Path) -> None:
        """A dict vocab targeting pattern-regex reads the standalone terms.

        Kills L231 `==`->`!=` (pattern-regex target guard).
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump({"checks": [{"id": "X.0001.d", "type": "deterministic", "pattern-regex": "(?:a|b)"}]}),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": {"pattern-regex": ["a", "b"]}}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unrelated_target_reads_no_terms(self, tmp_path: Path) -> None:
        """A pattern-not-regex target on a pattern-regex-only check finds no
        current terms -> stale.

        Kills L231 `and`->`or`: with `or`, the standalone pattern-regex would
        be read for an unrelated target and (matching) mask the staleness.
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump({"checks": [{"id": "X.0001.d", "type": "deterministic", "pattern-regex": "(?:a|b)"}]}),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": {"pattern-not-regex": ["a", "b"]}}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is True

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_target_absent_from_patterns_entry_is_stale(self, tmp_path: Path) -> None:
        """A pattern-regex target absent from the sole patterns entry -> stale.

        Kills L236 `and`->`or`: `target in entry and not is_guard(entry[target])`
        must short-circuit; `or` evaluates `entry[target]` on a missing key.
        """
        (tmp_path / "checks.yml").write_text(
            yaml.dump(
                {
                    "checks": [
                        {
                            "id": "X.0001.d",
                            "type": "deterministic",
                            "patterns": [{"pattern-not-regex": "(?:a|b)"}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "vocab.yml").write_text(yaml.dump({"d": {"pattern-regex": ["a", "b"]}}), encoding="utf-8")
        result = check_staleness(tmp_path)
        assert result is not None
        assert result.stale is True

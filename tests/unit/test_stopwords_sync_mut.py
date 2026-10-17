"""Mutation-closing tests for `core/classify/stopwords_sync.py`.

Each test pins a behavioral output (result.updated / result.skipped, or the written checks.yml
content) that a specific injected operator mutation flips, so the test reddens the moment that
bug returns. Derived from the mutation probe over `stopwords_sync.py`; targets the sync-dispatch
and targeted-field branches the existing suite left uncovered.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from reporails_cli.core.classify.stopwords_sync import (
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


class TestNonTextVocabTerm:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_term_yaml_reads_as_non_text_writes_no_pattern(self, tmp_path: Path) -> None:
        """`yes`, `no` and `404` are not text to YAML; the entry is skipped, named, and the file untouched."""
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text("words: [yes, maybe, perhaps, no, 404]\n", encoding="utf-8")
        before = (tmp_path / "checks.yml").read_text(encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (0, 1)
        assert result.messages == [
            "'words': item 1 reads as true/false (yes, no, on, off, true and false all do), not text; "
            "quote it. No pattern written",
            "'words': item 4 reads as true/false (yes, no, on, off, true and false all do), not text; "
            "quote it. No pattern written",
            "'words': item 5 reads as the number 404, not text; quote it. No pattern written",
        ]
        assert (tmp_path / "checks.yml").read_text(encoding="utf-8") == before


class TestEverySkippedEntryIsNamed:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        ("vocab", "messages"),
        [
            (
                "words:\n  pattern-regex:\n    - a\n    -\n    - c\n",
                ["'words' pattern-regex: item 2 is empty; remove it. No pattern written"],
            ),
            ("words:\n", ["'words': is empty; give it a list of terms. No pattern written"]),
            ("words: []\n", ["'words': is empty; give it a list of terms. No pattern written"]),
            (
                "words: {pattern-regex: []}\n",
                ["'words' pattern-regex: is empty; give it a list of terms. No pattern written"],
            ),
            (
                "words: [a, .nan]\n",
                ["'words': item 2 reads as a special number (.nan or .inf), not text; quote it. No pattern written"],
            ),
            ("words: maybe\n", ["'words': holds a single value, not a list of terms. No pattern written"]),
            (
                "words: {pattern-regex: 404}\n",
                ["'words' pattern-regex: holds a single value, not a list of terms. No pattern written"],
            ),
            ("words: {}\n", ["'words': names no field; give it a list of terms. No pattern written"]),
            (
                "words: [a, 12:30, 12:30]\n",
                [
                    "'words': item 2 reads as the number 750, not text; quote it. No pattern written",
                    "'words': item 3 reads as the number 750, not text; quote it. No pattern written",
                ],
            ),
            (
                "words: [a, [b], {c: d}]\n",
                [
                    "'words': item 2 is a nested list, not text. No pattern written",
                    "'words': item 3 is a nested mapping, not text. No pattern written",
                ],
            ),
        ],
    )
    def test_each_offending_item_and_each_skipped_shape_has_a_message(
        self, tmp_path: Path, vocab: str, messages: list[str]
    ) -> None:
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text(vocab, encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (0, 1)
        assert result.messages == messages

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_entry_already_in_sync_is_silent_and_not_skipped(self, tmp_path: Path) -> None:
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text("words: [old, word]\n", encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped, result.messages) == (0, 0, [])

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_field_no_pattern_takes_is_named_beside_a_field_that_updated(self, tmp_path: Path) -> None:
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text(
            "words:\n  pattern-regex: [old, word, new]\n  pattern-regx: [x, y]\n", encoding="utf-8"
        )

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (1, 0)
        assert result.messages == ["'words' pattern-regx: no pattern of the check takes this field"]
        assert "(?:old|word|new)" in (tmp_path / "checks.yml").read_text(encoding="utf-8")

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_plain_list_no_pattern_takes_is_skipped_and_named(self, tmp_path: Path) -> None:
        check = {"id": "CORE.S.1.words", "type": "semantic"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text("words: [a, b]\n", encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (0, 1)
        assert result.messages == ["'words': no pattern of the check takes these terms"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_invalid_field_stops_a_good_field_of_the_same_entry_from_writing(self, tmp_path: Path) -> None:
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text(
            "words:\n  pattern-regex: [old, word, new]\n  pattern-not-regex: []\n", encoding="utf-8"
        )
        before = (tmp_path / "checks.yml").read_text(encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (0, 1)
        assert result.messages == ["'words' pattern-not-regex: is empty; give it a list of terms. No pattern written"]
        assert (tmp_path / "checks.yml").read_text(encoding="utf-8") == before

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_pattern_that_is_not_an_alternation_is_named_not_skipped_silently(self, tmp_path: Path) -> None:
        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": "^---"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text("words: [a, b]\n", encoding="utf-8")

        result = sync_vocab(tmp_path)

        assert (result.updated, result.skipped) == (0, 1)
        assert result.messages == [
            "'words': the pattern '^---' is not an alternation of terms; it cannot take terms. No pattern written"
        ]


class TestStopwordsSyncCommandShowsWhySkipped:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_the_reason_an_entry_is_skipped_is_printed(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from reporails_cli.interfaces.cli.stopwords_command import stopwords_app

        check = {"id": "CORE.S.1.words", "type": "deterministic", "pattern-regex": r"\b(?:old|word)\b"}
        (tmp_path / "checks.yml").write_text(yaml.dump({"checks": [check]}), encoding="utf-8")
        (tmp_path / "vocab.yml").write_text("words: [yes, maybe, perhaps, no, 404]\n", encoding="utf-8")

        result = CliRunner().invoke(stopwords_app, ["sync", "--rules-root", str(tmp_path)])

        plain = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "item 5 reads as the number 404, not text; quote it" in plain

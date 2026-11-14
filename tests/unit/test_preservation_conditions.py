"""`added_conditions`: a matched instruction is listed only when its conditional rewrite brings a
content word the author's own line does not have."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from reporails_cli.core.heal.preservation import compare, take_snapshot
from reporails_cli.core.heal.preservation.conditions import added_conditions, dropped_conditions, hedge_made_absolute
from reporails_cli.core.mapper.classify_lexicon import CONDITION_OPENERS
from reporails_cli.core.platform.adapters.project_environment import LocalProjectEnvironment
from reporails_cli.core.platform.dto.heal import Pair, Snapshot, SnapshotAtom
from reporails_cli.core.platform.dto.ruleset import AtomSlots
from tests.unit.test_preservation import _atom


def _listed(
    original_line: list[SnapshotAtom], rewrite_text: str, *, index: int = 0, slots: AtomSlots | None = None
) -> bool:
    """Whether `original_line[index]` is listed when it matches a conditional rewrite; `slots` are
    the spans the mapper records on the rewrite (the real atom always carries them)."""
    sa = original_line[index]
    words = rewrite_text.split()
    # The scope the mapper decodes for a condition that follows its clause: from the opener to the end.
    opener = next((i for i, w in enumerate(words) if i and w.lower().strip(".,") in CONDITION_OPENERS), None)
    slots = slots or (
        None
        if opener is None
        else AtomSlots(predicate_span=(0, 1), object_span=(1, opener), scope_span=(opener, len(words)))
    )
    match = SimpleNamespace(
        line=sa.line,
        text=rewrite_text,
        plain_text=rewrite_text,
        named_tokens=(),
        scope_conditional=True,
        slots=slots,
    )
    return bool(added_conditions(original_line, {id(sa): match}))


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_rewrite_with_no_new_content_word_is_not_listed() -> None:
    line = [_atom(3, "Run pytest before every commit.", 1)]
    assert not _listed(line, "Before every commit, run pytest.")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_rewrite_with_one_new_content_word_is_listed() -> None:
    line = [_atom(3, "Run pytest before every commit.", 1)]
    slots = AtomSlots(scope_span=(0, 3), predicate_span=(3, 4), object_span=(4, 6))  # mapper dump
    assert _listed(line, "Before every commit, run pytest nightly.", slots=slots)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_plural_or_singular_form_of_an_original_word_is_not_new() -> None:
    line = [_atom(3, "Use real objects in tests.", 1)]
    assert not _listed(line, "Whenever it is a test, use real object.")
    assert not _listed([_atom(3, "Use real object in test.", 1)], "When in tests, use real objects.")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_difference_in_marker_words_only_is_not_listed() -> None:
    line = [_atom(3, "Regenerate the client every time openapi changes.", 1)]
    assert not _listed(line, "Regenerate the client whenever openapi changes.")
    assert not _listed(
        [_atom(3, "Run the seed script as soon as the migration lands.", 1)],
        "Once the migration lands, run the seed script.",
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_other_parts_of_the_authors_line_count_as_the_authors_words() -> None:
    line = [
        _atom(3, "Run pytest", 1),
        _atom(3, "Run ruff check before every commit", 1, scope_conditional=True),
    ]
    assert not _listed(line, "Run pytest before every commit.")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_word_only_another_line_has_is_new() -> None:
    line = [_atom(3, "Use real objects in tests.", 1), _atom(5, "Touch the database sparingly.", 1)]
    slots = AtomSlots(  # mapper dump
        subject_span=(4, 5), predicate_span=(0, 1), object_span=(1, 5), scope_span=(5, 11)
    )
    assert _listed(line, "Use real objects in tests whenever a test touches the database.", slots=slots)


_ROWS = [
    # (name, original, rewrite, listed)
    ("split in two lines", "Run `pytest` and `ruff check` before every commit.",
     "Run `pytest` before every commit.\n\nRun `ruff check` before every commit.", False),
    ("prior to", "Run `pytest` and `ruff check` prior to opening a pull request.",
     "Before opening a pull request, run `pytest` and `ruff check`.", False),
    ("in case", "Restore the backup in case the build fails.", "If the build fails, restore the backup.", False),
    ("every time", "Regenerate the client every time `openapi.yaml` changes.",
     "Regenerate the client whenever `openapi.yaml` changes.", False),
    ("as soon as", "Run the seed script as soon as the migration lands.",
     "Run the seed script once the migration lands.", False),
    ("whenever added", "Use real objects in tests.",
     "Use real objects in tests whenever a test touches the database.", True),
    ("before each commit added", "Use real objects in tests.",
     "Use real objects in tests before each commit on this branch.", True),
    ("if file is python added", "Format the code.", "If the file is Python, format the code.", True),
]  # fmt: skip


@pytest.mark.subsys_server
@pytest.mark.integration
@pytest.mark.requires_model
@pytest.mark.parametrize(("name", "original", "rewrite", "listed"), _ROWS, ids=[r[0] for r in _ROWS])
def test_added_conditions_on_the_real_mapper(tmp_path, name: str, original: str, rewrite: str, listed: bool) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    target = tmp_path / "CLAUDE.md"
    before_text, after_text = f"# Agent\n\n{original}\n", f"# Agent\n\n{rewrite}\n"
    target.write_text(before_text, encoding="utf-8")
    before_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    snap = take_snapshot(str(target), before_text, before_map, 5.0)
    assert isinstance(snap, Snapshot)
    target.write_text(after_text, encoding="utf-8")
    after_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    result = compare(snap, after_map, after_text, 5.0, environment=LocalProjectEnvironment(tmp_path))
    assert bool(result["added_conditions"]) is listed


def _hedge_pair(old_text: str, new_text: str, new_modality: str = "absolute") -> Pair:
    old = _atom(3, old_text, 1, modality="hedged")
    new = SimpleNamespace(line=3, text=new_text, plain_text=new_text, modality=new_modality, slots=None)
    return Pair(old, new, old_text, new_text)


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("word", ["Never", "Always"])
def test_a_hedge_made_never_or_always_is_listed(word: str) -> None:
    pair = _hedge_pair("You should run the linter.", f"{word} run the linter.")
    assert hedge_made_absolute([pair], {3: [pair.old]}) == [pair.entry()]


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("word", ["must", "shall"])
def test_a_hedge_made_must_or_shall_is_not_an_absolute(word: str) -> None:
    # the mapper reads `You must run the linter.` as `direct` (and `You shall …` as no instruction)
    pair = _hedge_pair("You should run the linter.", f"You {word} run the linter.", "direct")
    assert hedge_made_absolute([pair], {3: [pair.old]}) == []


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("word", ["must", "shall"])
def test_must_and_shall_are_no_absolute_cue_in_a_rewrite_read_absolute(word: str) -> None:
    # `must` / `shall` read as absolute modality, but only `never` / `always` / `exclusively` are cues
    pair = _hedge_pair("You should run the linter.", f"You {word} run the linter.", "absolute")
    assert hedge_made_absolute([pair], {3: [pair.old]}) == []


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("original", "rewrite", "dropped"),
    [
        (
            "If the build or the tests fail, stop the release.",
            "If the tests or the build fail, stop the release.",
            False,
        ),
        ("If the build or the tests fail, stop the release.", "If the build fails, stop the release.", True),
        ("If the build or the tests fail, stop the release.", "If the build or the docs fail, stop the release.", True),
    ],
)
def test_reordered_joined_conditions_hold(original: str, rewrite: str, dropped: bool) -> None:
    old = SimpleNamespace(line=1, plain_text=original, named_tokens=(), scope_conditional=True, slots=None)
    new = SimpleNamespace(line=1, plain_text=rewrite, named_tokens=(), scope_conditional=True, slots=None)
    assert bool(dropped_conditions([Pair(old, new, original, rewrite)])) is dropped


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("original", "rewrite", "named", "dropped"),
    [
        (
            "Before writing prd.json, verify the stories.",
            "Before writing prd.json, verify the stories.",
            ("prd.json",),
            False,
        ),
        (
            "Prefer EAFP (try/except) over LBYL (if/then check) for high-level logic.",
            "Use EAFP (try/except) instead of LBYL (if/then check) for high-level logic.",
            ("try", "except"),
            False,
        ),
        (
            "Prefer EAFP (try/except) over LBYL (if/then check) for high-level logic.",
            "Use EAFP (try/except) instead of LBYL (if/then check) for high-level logic.",
            ("try", "except", "if"),
            False,
        ),
        (
            "Only use on trusted machines and close Chrome when done.",
            "Only use remote debugging on trusted machines and close Chrome when done.",
            (),
            False,
        ),
        ("Only run unit tests.", "Run unit tests.", (), True),
        ("Run all tests except integration tests.", "Run all tests except slow integration tests.", (), True),
        ("Run all tests except integration tests.", "Run all tests.", (), True),
        ("Run all tests except integration tests.", "Run all tests except the integration tests.", (), False),
        ("If the build fails, run make clean.", "Run make clean.", (), True),
        ("If the build fails, run make clean.", "If the build passes, run make clean.", (), True),
        ("When tests fail and the branch is main, stop.", "When tests fail, stop.", (), True),
        ("If the build fails and the branch is main, stop.", "If it fails, stop.", (), True),
        ("If the build fails, stop.", "If it fails, stop.", (), False),
        ("If in CI, run lint.", "Run lint.", (), True),
    ],
)
def test_a_name_in_backticks_or_a_named_object_never_changes_a_condition(
    original: str, rewrite: str, named: tuple[str, ...], dropped: bool
) -> None:
    old = SimpleNamespace(line=1, plain_text=original, named_tokens=(), scope_conditional=True, slots=None)
    new = SimpleNamespace(line=1, plain_text=rewrite, named_tokens=named, scope_conditional=True, slots=None)
    assert bool(dropped_conditions([Pair(old, new, original, rewrite)])) is dropped


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("original", "rewrite", "ok"),
    [
        ("Before writing prd.json, verify the stories.", "Before writing `prd.json`, verify the stories.", True),
        (
            "- Prefer EAFP (try/except) over LBYL (if/then check) for high-level logic (file access)",
            "- Use EAFP (`try`/`except`) instead of LBYL (`if`/then check) for high-level logic (file access)",
            True,
        ),
        (
            "Only use on trusted machines and close Chrome when done.",
            "Only use remote debugging on trusted machines and close Chrome when done.",
            True,
        ),
        ("Only use on trusted machines.", "Only use on any machine.", False),
        ("Run all tests except integration tests.", "Run all tests except slow integration tests.", False),
        ("Wrap file reads in `try`/`except`.", "Wrap file reads in try/except.", True),
        ("Only run unit tests.", "Run unit tests.", False),
        ("If the build fails and the branch is main, stop.", "If it fails, stop.", False),
        ("If in CI, run lint.", "Run lint.", False),
        (
            "Check the tool list for the `reporails` MCP `explain` tool first (its name ends in `reporails__explain`).",
            "Check the tool list for the `reporails` MCP `explain` tool first (its name ends in `reporails__explain`).",
            True,
        ),
        (
            "Check the tool list for the `reporails` MCP `explain` tool first (its name ends in `reporails__explain`).",
            "Check the tool list for the `reporails` MCP `explain` tool first"
            " (its name ends in `reporails__explain`) in `src/`.",
            False,
        ),
    ],
)
def test_condition_verdicts_on_the_real_mapper(tmp_path, original: str, rewrite: str, ok: bool) -> None:
    from tests.unit.test_preservation import _compare_edit

    assert _compare_edit(tmp_path, f"# Agent\n\n{original}\n", f"# Agent\n\n{rewrite}\n")["ok"] is ok


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("original", "old_named", "rewrite", "new_named", "dropped", "narrowed", "slots"),
    [
        (
            "Wrap file reads in `try`/`except`.",
            ("try", "except"),
            "Catch errors on file reads.",
            (),
            False,
            False,
            # the slots the mapper reads: `Catch` over `errors`, where `Wrap` has `file reads in try/except`
            (
                AtomSlots(predicate_span=(0, 1), object_span=(1, 5)),
                AtomSlots(predicate_span=(0, 1), object_span=(1, 2)),
            ),
        ),
        (
            "Wrap file reads in `try`/`except`.",
            ("try", "except"),
            "Wrap file reads in try/except.",
            (),
            False,
            False,
            (None, None),
        ),
        (
            "Run the linter, configured in `src/lint.toml`.",
            ("src/lint.toml",),
            "Run the linter on src, configured in `src/lint.toml`.",
            ("src/lint.toml",),
            False,
            True,
            (None, None),
        ),
        (
            "Deploy with `deploy.sh staging`.",
            ("deploy.sh staging",),
            "Deploy with `deploy.sh staging` in staging.",
            ("deploy.sh staging",),
            False,
            True,
            (None, None),
        ),
    ],
)
def test_a_code_token_never_opens_a_condition_or_narrows(
    original: str,
    old_named: tuple[str, ...],
    rewrite: str,
    new_named: tuple[str, ...],
    dropped: bool,
    narrowed: bool,
    slots: tuple[AtomSlots | None, AtomSlots | None],
) -> None:
    from reporails_cli.core.heal.preservation.conditions import by_line, narrowed_instructions

    old = _atom(1, original, 1, named=old_named, slots=slots[0])
    new = SimpleNamespace(
        line=1,
        plain_text=rewrite,
        named_tokens=new_named,
        scope_conditional=False,
        slots=slots[1],
        charge_value=1,
        modality="direct",
        heading_context="",
    )
    pair = Pair(old, new, original, rewrite)
    assert bool(dropped_conditions([pair])) is dropped
    assert bool(narrowed_instructions([pair], by_line([old]))) is narrowed


@pytest.mark.subsys_map
@pytest.mark.integration
@pytest.mark.requires_model
def test_whole_line_quotation_maps_as_one_neutral_atom(tmp_path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    quote = (
        '"Answer every question: each answer states its source. Quote every figure, date, name; '
        'round one only when the reader asks for it. Add no preamble and speculate on nothing."'
    )
    target = tmp_path / "CLAUDE.md"
    target.write_text(f"# T\n\n## Contract\n\n{quote}\n\nRun `pytest` before every commit in this repository.\n")
    mapped = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    on_line = [a for a in mapped.atoms if a.line == 5]
    assert len(on_line) == 1
    assert on_line[0].charge_value == 0


_QUOTE_LINE = (
    '"Answer every question: each answer states its source. Quote every figure, date, name; '
    'round one only when the reader asks for it. Add no preamble and speculate on nothing."'
)


@pytest.mark.subsys_map
@pytest.mark.unit
def test_whole_line_quotation_stays_one_atom_under_structure_aware_tokenize() -> None:
    from reporails_cli.core.mapper.parse import tokenize
    from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE

    text = f"# T\n\n## Contract\n\n{_QUOTE_LINE}\n\nRun `pytest` before every commit in this repository.\n"
    on_line = [a for a in tokenize(text, SEGMENTATION_STRUCTURE_AWARE) if a.line == 5]
    assert len(on_line) == 1
    assert on_line[0].charge_value == 0


@pytest.mark.subsys_map
@pytest.mark.unit
def test_quotation_followed_by_text_still_splits_under_structure_aware() -> None:
    from reporails_cli.core.mapper.parse import tokenize
    from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE

    text = '# T\n\n"Use the cache." Then run the tests.\n'
    assert len([a for a in tokenize(text, SEGMENTATION_STRUCTURE_AWARE) if a.line == 3]) > 1


@pytest.mark.subsys_map
@pytest.mark.integration
@pytest.mark.requires_model
def test_whole_line_quotation_maps_as_one_neutral_atom_structure_aware(tmp_path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset
    from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE

    target = tmp_path / "CLAUDE.md"
    target.write_text(f"# T\n\n## Contract\n\n{_QUOTE_LINE}\n\nRun `pytest` before every commit in this repository.\n")
    mapped = map_ruleset(
        [target], models=get_models(), root=tmp_path, cache_dir=None, segmentation=SEGMENTATION_STRUCTURE_AWARE
    )
    on_line = [a for a in mapped.atoms if a.line == 5]
    assert len(on_line) == 1
    assert on_line[0].charge_value == 0

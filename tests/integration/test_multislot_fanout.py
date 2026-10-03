"""Multi-atom charge-run decode — real bundled model.

The 7-tag charge BIO segments a sentence into atoms (one atom per charge B-run);
each atom carries its own charge, its own text (the run's extent), and spans
whose offsets are rebased to index the atom's OWN text. This guards two invariants
end-to-end on the real model: per-atom charge (not one sentence-level charge shared
across atoms) and the span-offset↔atom-text alignment. Real model, no stubs — the
segmentation mechanism itself (multi-run, class-flip noise) is unit-tested with
synthetic inputs, since a single mapped sentence yields one atom here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reporails_cli.core.mapper.bio_pipeline import _decode_plan
from reporails_cli.core.mapper.bio_tagger import multislot_available
from reporails_cli.core.mapper.multislot_frames import tag_atom_multislot_frames
from reporails_cli.core.mapper.parse import tokenize

requires_charge_model = pytest.mark.skipif(
    not multislot_available(), reason="Bundled charge-model graphs not available"
)

_CONSTRAINT = "Never push to main."
_DIRECTIVE = "Add backtick-wrapped names to your instructions."


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_atom_charge_is_per_run_from_the_charge_bio() -> None:
    """Each atom's charge is its charge-run class — a constraint is -1, a directive +1."""
    (con,) = tag_atom_multislot_frames(_CONSTRAINT)
    assert con.polarity == -1 and con.modality != "none"
    (dir_,) = tag_atom_multislot_frames(_DIRECTIVE)
    assert dir_.polarity == 1 and dir_.modality != "none"


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_span_offsets_index_the_atom_own_text() -> None:
    """Every non-empty span offset indexes into the atom's OWN text, not the sentence.

    This is the invariant the earlier full-sentence-vs-sub-slice code broke: offsets
    are rebased to atom-local words, so slicing the atom text by a span's offset lands
    on that span's words.
    """
    for text in (_CONSTRAINT, _DIRECTIVE, "Reporails recognizes agent files and runs the validator."):
        for atom in tag_atom_multislot_frames(text):
            words = [m.group() for m in re.finditer(r"\S+", atom.text)]
            for span in (atom.subject, atom.predicate, atom.object, atom.scope):
                if span.offset is None:
                    assert span.text == ""
                    continue
                s, e = span.offset
                assert 0 <= s < e <= len(words), f"offset {span.offset} out of atom words {words}"
                local = " ".join(words[s:e])
                assert span.text.strip(".,;") in local or local in span.text, (
                    f"span {span.text!r} != atom-local slice {local!r}"
                )


# ── word coverage: no atom silently drops a word the head tagged O ──────────
# The charge run's own B/I extent almost never covers a whole unit — words the
# head left untagged (`O`) sit outside every run's own span.
# `_widen_runs_to_cover` folds them into
# a neighbouring run's text so the unit's full word content survives the decode.


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
@pytest.mark.parametrize(
    "text",
    [
        "The helper always_run() returns a flag.",
        "agent-specific rules require an explicit flag.",
    ],
)
def test_charge_run_atoms_cover_the_full_unit(text: str) -> None:
    """Every word of the source unit is present in the union of its atoms' text."""
    frames = tag_atom_multislot_frames(text)
    src_words = text.split()
    atom_words = [w for f in frames for w in f.text.split()]
    assert atom_words == src_words, (text, [f.text for f in frames])


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_two_run_sentence_partitions_with_no_gap() -> None:
    """A sentence the head splits into two charge runs: the atoms tile the unit with no gap."""
    text = "Broken imports create gaps in the agent's context — the agent silently skips missing files without warning."
    frames = tag_atom_multislot_frames(text)
    assert len(frames) >= 2, "fixture no longer produces multiple charge runs — pick a new one"
    assert " ".join(f.text for f in frames) == text


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_corpus_sample_drops_no_words() -> None:
    """Property test over a sample of this repo's own instruction files: zero dropped words.

    Mirrors the corpus measurement: every sentence the classifier
    decodes must come back covered by the union of its resulting atoms' words.
    """
    root = Path(__file__).resolve().parents[2] / "framework" / "rules"
    sample = sorted(root.rglob("*.md"))[:40]
    assert sample, "no sample files found under framework/rules"

    dropped_units: list[tuple[str, list[str]]] = []
    total_units = 0
    for path in sample:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        atoms = tokenize(content)
        texts, plan = _decode_plan(atoms)
        for entry in plan:
            if entry[0] != "sent":
                continue
            _, _atom, _plain, start, units = entry
            for t in texts[start : start + len(units)]:
                src_words = t.split()
                if not src_words:
                    continue
                total_units += 1
                frames = tag_atom_multislot_frames(t)
                atom_word_count = sum(len(f.text.split()) for f in frames)
                if atom_word_count < len(src_words):
                    dropped_units.append((t, [f.text for f in frames]))

    assert total_units > 0
    assert not dropped_units, f"{len(dropped_units)}/{total_units} units dropped a word: {dropped_units[:5]}"


# ── truncation past the encoder's token budget must not fabricate a sign ────
# `_BioEncoder` truncates at 128 tokens; a word entirely past that cut has no
# real token behind it, so its BIO logits come from the whole-text fallback
# vector, not its own content. A prohibition living in that tail must not be
# silently absorbed into an earlier, unrelated, oppositely-signed run.


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_truncated_tail_prohibition_is_not_swallowed_as_directive() -> None:
    filler = " ".join(f"word{i}" for i in range(150))
    text = f"Always run the tests before committing and {filler} but never delete the production database."
    frames = tag_atom_multislot_frames(text)
    # The prohibition text must survive somewhere in the atom set (word coverage)...
    assert any("never delete the production database" in f.text for f in frames)
    # ...and it must never ride a +1 (DIRECTIVE) atom — neutral or its own -1 are both acceptable.
    for f in frames:
        if "never delete the production database" in f.text:
            assert f.polarity != 1, (f.polarity, f.text)

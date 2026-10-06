"""A unit carrying no letter or digit is not an instruction and must not survive.

Every downstream stage treats an atom as an instruction: it is charge-classified,
embedded, grouped into a topic, and counted in the per-file measures. A run of
bare markers that reaches that pipeline dilutes each of those without carrying
anything to say. The upstream length floor counts characters, which a repeated
marker clears at any length, so content is what has to decide.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.parse import tokenize

_MARKER_ONLY = """Ship the build.

» » » »

-> -> ->

1. 2. 3. 4.

... ... ...

Run the tests.
"""


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("segmentation", ["legacy", "structure-aware"])
def test_marker_runs_never_become_units(segmentation: str) -> None:
    """Marker paragraphs long enough to clear the length floor still drop out."""
    atoms = tokenize(_MARKER_ONLY, segmentation=segmentation)
    assert [a.text for a in atoms] == ["Ship the build.", "Run the tests."]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("segmentation", ["legacy", "structure-aware"])
def test_no_unit_is_ever_contentless(segmentation: str) -> None:
    """The invariant, stated directly against a document built to violate it."""
    atoms = tokenize(_MARKER_ONLY, segmentation=segmentation)
    assert all(any(ch.isalnum() for ch in a.text) for a in atoms)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_marker_keeps_the_sentence_it_decorates() -> None:
    """Dropping the unit must not drop the text beside it."""
    atoms = tokenize("Try the playground! »\n", segmentation="structure-aware")
    assert len(atoms) == 1
    assert atoms[0].text.startswith("Try the playground!")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_positions_stay_contiguous_after_a_drop() -> None:
    """A dropped unit must not leave a hole in the position index.

    Position drives ordering and the position-weighted measures, so a gap would
    silently shift every unit after the drop.
    """
    atoms = tokenize(_MARKER_ONLY, segmentation="structure-aware")
    positions = [a.position_index for a in atoms if a.kind != "heading"]
    assert positions == list(range(len(positions)))


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_bare_figure_is_not_content() -> None:
    """A number means something only through the words around it.

    `-> 3 <-` gives the embedder nothing to place, so it is a marker run like any
    other. The figure survives only when a word carries it.
    """
    markers = tokenize("Set the retry budget.\n\n-> 3 <-\n", segmentation="structure-aware")
    assert [a.text for a in markers] == ["Set the retry budget."]

    carried = tokenize("Set the retry budget.\n\nRetry 3 times.\n", segmentation="structure-aware")
    assert any("Retry 3 times." in a.text for a in carried)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_non_latin_instruction_is_content() -> None:
    """`isalpha` is Unicode-wide, so a non-Latin script is never read as a marker."""
    atoms = tokenize("Ship the build.\n\n変更を確認してください。\n", segmentation="structure-aware")
    assert any("変更" in a.text for a in atoms)

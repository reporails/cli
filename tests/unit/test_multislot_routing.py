"""The multi-slot path reads the right graph for the right job.

The first graph drives charge+modality; the second drives the subject/object/predicate/
scope spans (+ compound). These guards redden if the wiring is crossed (the wrong
graph used for a job, or one graph reused for both) or if the two graphs are
configured to the same file.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import bio_tagger


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_the_four_graphs_are_distinct_files() -> None:
    paths = [
        bio_tagger._enc_a_path(),
        bio_tagger._head_a_path(),
        bio_tagger._enc_b_path(),
        bio_tagger._head_b_path(),
    ]
    assert len({str(p) for p in paths}) == 4  # no graph aliased to another's file


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_charge_pass_reads_the_first_graph_and_span_pass_reads_the_second(monkeypatch) -> None:
    if not bio_tagger.multislot_available():
        pytest.skip("charge-classifier graphs not bundled")
    enc_a, enc_b = bio_tagger._enc_a(), bio_tagger._enc_b()
    assert enc_a is not enc_b

    seen: list[object] = []
    real = bio_tagger._word_features

    def spy(text: str, encoder=None):
        seen.append(encoder)
        return real(text, encoder=encoder)

    monkeypatch.setattr(bio_tagger, "_word_features", spy)
    bio_tagger.tag_atom_multislot("Do not commit secrets to the repository.")
    # First extraction pass reads the first graph; second reads the second.
    assert seen == [enc_a, enc_b]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_object_and_predicate_axes_are_renamed_not_dropped() -> None:
    # The consumer-side rename must map both legacy graph axes; a missing entry
    # would silently blank the object or predicate span.
    assert bio_tagger._MULTISLOT_RENAME == {
        "logits_target": "logits_object",
        "logits_action": "logits_predicate",
    }

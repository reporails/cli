"""The multi-slot path reads the right graph for the right job.

The first graph drives charge+modality; the second drives the subject/object/predicate/
scope spans (+ compound). These guards redden if the wiring is crossed (the wrong
graph used for a job, or one graph reused for both) or if the two graphs are
configured to the same file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper import bio_graphs, bio_tagger, multislot_frames


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_the_four_graphs_are_distinct_files() -> None:
    paths = [
        bio_graphs._enc_a_path(),
        bio_graphs._head_a_path(),
        bio_graphs._enc_b_path(),
        bio_graphs._head_b_path(),
    ]
    assert len({str(p) for p in paths}) == 4  # no graph aliased to another's file


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_charge_pass_reads_the_first_graph_and_span_pass_reads_the_second(monkeypatch) -> None:
    if not bio_graphs.multislot_available():
        pytest.skip("charge-classifier graphs not bundled")
    seen: list[tuple[Path, tuple[str, ...]]] = []
    real = multislot_frames._extract_pass_from_states

    def spy(hidden, offsets, text, head_path, outputs):
        seen.append((head_path, tuple(outputs)))
        return real(hidden, offsets, text, head_path, outputs)

    monkeypatch.setattr(multislot_frames, "_extract_pass_from_states", spy)
    multislot_frames._decode_logits_batch(["Do not commit secrets to the repository."])
    # First extraction pass reads the first head for charge+modality; second reads the second for the spans.
    assert seen == [
        (bio_graphs._head_a_path(), bio_tagger.CHARGE_OUTPUTS),
        (bio_graphs._head_b_path(), bio_tagger.SPAN_OUTPUTS),
    ]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_object_and_predicate_axes_are_renamed_not_dropped() -> None:
    # The consumer-side rename must map both legacy graph axes; a missing entry
    # would silently blank the object or predicate span.
    assert bio_tagger._MULTISLOT_RENAME == {
        "logits_target": "logits_object",
        "logits_action": "logits_predicate",
    }

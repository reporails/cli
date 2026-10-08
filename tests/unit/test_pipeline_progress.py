"""Progress-emission SEAM for the mapper's per-harness-element counter.

`_classify_all_files` emits `Mapping <element>: <i>/<n>` as it walks the file set,
so a caller's spinner advances through the map instead of parking on one label.
These stub the heavy per-file classify calls and assert the emitted counter
strings — they redden if the denominator, the per-element index, the element
coarsening, or the None-guard breaks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper import pipeline


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("CLAUDE.md", "main"),  # root-level main file
        ("sub/CLAUDE.md", "nested"),  # a subdir copy is nested, not main
        (".claude/agents/reviewer.md", "agents"),
        (".claude/rules/naming.md", "rules"),
        (".claude/skills/deploy/SKILL.md", "skills"),
    ],
)
def test_element_label_coarsens_to_harness_group(path: str, expected: str) -> None:
    assert pipeline._element_label(Path(path)) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_element_label_root_main_is_main_on_absolute_paths(tmp_path: Path) -> None:
    """Regression: discovery yields ABSOLUTE paths, so the len(parts)<=1 heuristic
    mislabeled the root CLAUDE.md as `nested`. With the scan root threaded through,
    the top-level main file must read `main` and a subdir copy `nested`."""
    (tmp_path / "CLAUDE.md").write_text("# root", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "CLAUDE.md").write_text("# nested", encoding="utf-8")
    root_main = (tmp_path / "CLAUDE.md").resolve()
    nested_main = (tmp_path / "sub" / "CLAUDE.md").resolve()
    assert pipeline._element_label(root_main, tmp_path) == "main"
    assert pipeline._element_label(nested_main, tmp_path) == "nested"


def _stub_classify(monkeypatch: pytest.MonkeyPatch) -> None:
    # Neuter the heavy per-file work; we are exercising only the progress counter.
    monkeypatch.setattr(
        pipeline, "_detect_file_activation", lambda *a, **k: ("always", "", (), "generic", "generic", "always")
    )
    monkeypatch.setattr(pipeline, "_classify_file", lambda *a, **k: "sha256:x")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_progress_emits_per_element_counter_with_correct_denominator(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_classify(monkeypatch)
    paths = [
        Path("CLAUDE.md"),
        Path(".claude/agents/one.md"),
        Path(".claude/agents/two.md"),
        Path(".claude/skills/s/SKILL.md"),
    ]
    msgs: list[str] = []
    pipeline._classify_all_files(paths, Path("."), None, {}, progress=msgs.append)
    assert msgs == [
        "Mapping main: 1/1",
        "Mapping agents: 1/2",
        "Mapping agents: 2/2",
        "Mapping skills: 1/1",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_progress_none_is_silent_and_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_classify(monkeypatch)
    # No progress callback: the map still classifies, emitting nothing.
    file_records, _all_atoms, _needing = pipeline._classify_all_files(
        [Path("CLAUDE.md"), Path(".claude/agents/one.md")], Path("."), None, {}
    )
    assert len(file_records) == 2

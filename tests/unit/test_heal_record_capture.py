"""What a project `validate` writes into the heal record: only covered, accepted, clean runs, once per acceptance."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.heal.record import read_record, regressions
from reporails_cli.interfaces.mcp import snapshots
from reporails_cli.interfaces.mcp.heal_record import record_kept_files

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]

TEXT = "# Project\n\n- Run `pytest`.\n"


def _payload(scores: dict[str, float], **extra: object) -> dict:
    return {"files": {name: {"findings": []} for name in scores}, "file_scores": scores, **extra}


@pytest.fixture
def root(tmp_path: Path) -> Path:
    for store in (snapshots._snapshots, snapshots._plans, snapshots._rule_counts, snapshots._accepted_text):
        store.clear()
    snapshots._released.clear()
    snapshots._recorded.clear()
    (tmp_path / "CLAUDE.md").write_text(TEXT, encoding="utf-8")
    (tmp_path / "OTHER.md").write_text(TEXT, encoding="utf-8")
    for name in ("CLAUDE.md", "OTHER.md"):
        snapshots.snapshot_file(tmp_path / name, None, None)
        snapshots.record_accepted(tmp_path / name, TEXT)
    return tmp_path


def test_a_file_the_run_did_not_cover_is_not_recorded(root: Path) -> None:
    record_kept_files(_payload({"CLAUDE.md": 8.4}), root)

    assert set(read_record(root)) == {"CLAUDE.md"}


@pytest.mark.parametrize(
    "flags", [{"offline": True}, {"server_error": {"code": "x"}}, {"content_checks_skipped": True}, {"error": "x"}]
)
def test_a_degraded_run_is_not_recorded(root: Path, flags: dict) -> None:
    record_kept_files(_payload({"CLAUDE.md": 8.4}, **flags), root)

    assert read_record(root) == {}


def test_a_run_without_file_scores_is_not_recorded(root: Path) -> None:
    record_kept_files({"files": {"CLAUDE.md": {"findings": []}}}, root)

    assert read_record(root) == {}


def test_names_keep_their_case_when_the_platform_folds_paths(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os.path, "normcase", str.lower)
    (root / "Docs").mkdir()
    guide = root / "Docs" / "Guide.md"
    guide.write_text(TEXT, encoding="utf-8")
    snapshots.snapshot_file(guide, None, None)
    snapshots.record_accepted(guide, TEXT)

    record_kept_files(_payload({"Docs/Guide.md": 7.0}), root)

    assert "Docs/Guide.md" in read_record(root)


def test_a_later_project_validate_does_not_overwrite_the_baseline(root: Path) -> None:
    record_kept_files(_payload({"CLAUDE.md": 8.4}), root)
    record_kept_files(_payload({"CLAUDE.md": 5.0}), root)

    record = read_record(root)
    assert record["CLAUDE.md"].score == 8.4
    assert [r.file for r in regressions(record, {"CLAUDE.md": 5.0}, {})] == ["CLAUDE.md"]


def test_a_new_acceptance_is_recorded_again(root: Path) -> None:
    record_kept_files(_payload({"CLAUDE.md": 8.4}), root)
    snapshots.record_accepted(root / "CLAUDE.md", TEXT)
    record_kept_files(_payload({"CLAUDE.md": 9.0}), root)

    assert read_record(root)["CLAUDE.md"].score == 9.0


def test_the_bounded_mcp_view_leaves_out_file_scores() -> None:
    from reporails_cli.formatters.mcp import bound_validate_payload

    bounded = bound_validate_payload({"files": {"A.md": {"findings": [], "count": 0}}, "file_scores": {"A.md": 5.0}})

    assert "file_scores" not in bounded

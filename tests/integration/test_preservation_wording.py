"""The word-level preservation checks on the real mapper: a hedge made direct is listed and passes;
a hedge turned into `Never` / `Always`, a narrowing with no condition word, a dropped condition,
an appended directive and a padded rewrite fail. Each row maps the original and the rewrite with
the bundled model and runs the whole `compare`."""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.core.heal.preservation import Snapshot, compare, take_snapshot
from reporails_cli.core.platform.adapters.project_environment import LocalProjectEnvironment


def _verdict(tmp_path, original: str, rewrite: str) -> dict[str, Any]:
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
    return compare(snap, after_map, after_text, 5.0, LocalProjectEnvironment(tmp_path))


_LIST = "- Run the tests.\n- Use real objects in tests.\n- Check the logs."
_FACTS = "The service uses `pytest` and Postgres.\nLogs go to stdout.\nDeploys run nightly.\nRun the linter."
_ROWS = [
    # (name, original, rewrite, ok, made_direct count)
    ("consider running", "Consider running `ruff check` before commits.", "Run `ruff check` before commits.", True, 1),
    ("consider avoiding to avoid", "Consider avoiding global state.", "Avoid global state.", True, 1),
    ("consider avoiding to do not", "Consider avoiding global state.", "Do not use global state.", True, 1),
    ("prefer", "Prefer real objects in tests.", "Use real objects in tests.", True, 1),
    ("try not to", "Try not to use global state.", "Do not use global state.", True, 1),
    ("might want", "You might want to run the linter before a commit.", "Run the linter before a commit.", True, 1),
    ("should always", "You should always run `pytest`.", "Always run `pytest`.", True, 1),
    ("should to must", "You should run `pytest` before commits.", "You must run `pytest` before commits.", True, 1),
    ("prefer to shall", "Prefer real objects in tests.", "Real objects shall be used in tests.", True, 1),
    ("prefer not to never", "Prefer not to mock the database.", "Never mock the database.", False, 1),
    (
        "should to always",
        "You should format the code with `ruff format`.",
        "Always format the code with `ruff format`.",
        False,
        1,
    ),
    (
        "on this branch",
        "Run `pytest tests/` before committing.",
        "Run `pytest tests/` before committing on this branch.",
        False,
        0,
    ),
    (
        "on fridays",
        "Deploy the service with `make deploy`.",
        "Deploy the service with `make deploy` on Fridays.",
        False,
        0,
    ),
    ("only for", "Use real objects in tests.", "Use real objects in tests only for the database layer.", False, 0),
    ("before dropped", "Run `pytest` before every commit.", "Run `pytest`.", False, 0),
    ("unless dropped", "Deploy with `make deploy` unless the freeze is on.", "Deploy with `make deploy`.", False, 0),
    (
        "duplicated list",
        "- Run the tests.\n- Use real objects in tests.\n- Check the logs.",
        _LIST + "\n" + _LIST,
        False,
        0,
    ),
    (
        "near-duplicate line",
        "Use real objects in tests.\nRun `pytest tests/` before commits.",
        "Use real objects in tests.\nRun `pytest tests/` before commits.\nUse real objects within tests.",
        False,
        0,
    ),
    (
        "appended directive",
        "The service uses `pytest` and Postgres.\nLogs go to stdout.\nDeploys run nightly.\nRun the linter.",
        _FACTS + "\nRun the service logs nightly.",
        False,
        0,
    ),
    (
        "condition changed",
        "If the build fails, run `make clean` before running `make build` again.",
        "If the build passes, run `make clean` before running `make build` again.",
        False,
        0,
    ),
    (
        "one of two joined conditions dropped",
        "When tests fail and the branch is main, stop the release.",
        "When tests fail, stop the release.",
        False,
        0,
    ),
    (
        "condition subject restated as a pronoun",
        "If the build fails, run `make clean` before running `make build` again.",
        "If it fails, run `make clean` before running `make build` again.",
        True,
        0,
    ),
    ("condition verb inflected", "Run the linter before committing.", "Run the linter before you commit.", True, 0),
    ("condition moved first", "Run `pytest` before every commit.", "Before every commit, run `pytest`.", True, 0),
    (
        "marker swapped",
        "Regenerate the client every time `openapi.yaml` changes.",
        "Regenerate the client whenever `openapi.yaml` changes.",
        True,
        0,
    ),
    (
        "split in two lines",
        "Run `pytest` and `ruff check` before every commit.",
        "Run `pytest` before every commit.\n\nRun `ruff check` before every commit.",
        True,
        0,
    ),
    ("elaboration", "Run the tests.", "Run the tests with `pytest tests/`.", True, 0),
    (
        "reason added",
        "Do not edit `generated/` files by hand.",
        "Do not edit `generated/` files by hand, because `make gen` overwrites them.",
        True,
        0,
    ),
    (
        "reordered",
        "Run `pytest`.\nFormat the code with `ruff format`.",
        "Format the code with `ruff format`.\nRun `pytest`.",
        True,
        0,
    ),
    ("avoid to do not", "Avoid global state.", "Do not use global state.", True, 0),
    (
        "ideally to run",
        "Ideally run `mypy` before opening a pull request.",
        "Run `mypy` before opening a pull request.",
        True,
        1,
    ),
    (
        "maybe to always",
        "Maybe lint the migrations with `sqlfluff`.",
        "Always lint the migrations with `sqlfluff`.",
        False,
        1,
    ),
    ("changelog only", "Write a changelog entry.", "Write a changelog entry for user-facing changes only.", False, 0),
    ("during the audit", "Rotate the API keys.", "Rotate the API keys during the quarterly audit.", False, 0),
    (
        "unless dropped squash",
        "Squash the commits unless the reviewer asks otherwise.",
        "Squash the commits.",
        False,
        0,
    ),
    ("while dropped", "Keep the cache warm while the migration runs.", "Keep the cache warm.", False, 0),
    ("if moved first", "Restart the worker if the queue stalls.", "If the queue stalls, restart the worker.", True, 0),
    (
        "if clause dropped before kept",
        "If the build fails, run `make clean` before running `make build` again.",
        "Run `make clean` before running `make build` again.",
        False,
        0,
    ),
    (
        "if clause restated with another marker",
        "If the build fails, run `make clean` before running `make build` again.",
        "Run `make clean` before running `make build` again, whenever the build fails.",
        True,
        0,
    ),
    (
        "padded after a four-backtick fence",
        "Run the tests.\nFormat the code.\n\n````md\n```\nExample.\n````",
        "Run the tests.\nFormat the code.\n\n````md\n```\nExample.\n````\n\nRun all the tests.\nFormat the code.",
        False,
        0,
    ),
    ("try to keep", "Try to keep pull requests small.", "Keep pull requests small.", True, 1),
    (
        "padded list",
        "- Pin the dependencies.\n- Review the lockfile.",
        "- Pin the dependencies.\n- Review the lockfile.\n- Pin all the dependencies.\n- Review the lockfile diff.",
        False,
        0,
    ),
]


@pytest.mark.subsys_server
@pytest.mark.integration
@pytest.mark.requires_model
@pytest.mark.parametrize(("name", "original", "rewrite", "ok", "direct"), _ROWS, ids=[r[0] for r in _ROWS])
def test_word_level_checks_on_the_real_mapper(
    tmp_path, name: str, original: str, rewrite: str, ok: bool, direct: int
) -> None:
    result = _verdict(tmp_path, original, rewrite)
    assert result["ok"] is ok
    if ok:
        assert len(result["made_direct"]) == direct


@pytest.mark.subsys_server
@pytest.mark.integration
@pytest.mark.requires_model
def test_a_hedge_made_direct_never_fails_the_rewrite_by_itself(tmp_path) -> None:
    result = _verdict(tmp_path, "Consider avoiding global state.", "Avoid global state.")
    assert result["lost_instructions"] == []
    assert result["made_direct"] == [
        {"line": 3, "text": "Consider avoiding global state.", "new_line": 3, "new_text": "Avoid global state."}
    ]

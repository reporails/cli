"""Mutation-killing behavioral tests for config loading (config.py).

Targets the boolean/default operators that survived the mutation probe:
coercion guards, YAML default literals, the deep-merge type gates, and the
global-inheritance precedence conditions. Each test asserts a value that
flips when the operator under it is mutated (verified against the probe).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.config.config import (
    _coerce_segmentation,
    _deep_merge_config,
    _merge_under,
    get_agent_config,
    get_project_config,
)


def _patch_reporails_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.REPORAILS_HOME",
        home,
    )


def _write_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text(body, encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)


def _no_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point REPORAILS_HOME at an empty dir so get_global_config returns defaults."""
    _patch_reporails_home(monkeypatch, tmp_path / ".reporails-absent")


# ---------------------------------------------------------------------------
# Coercion guards (L62, L74)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_coerce_segmentation_rejects_unknown_string() -> None:
    """A string that is not a known mode coerces to None (L62 `and->or`)."""
    assert _coerce_segmentation("nonsense-mode") is None
    assert _coerce_segmentation("legacy") == "legacy"


# ---------------------------------------------------------------------------
# Deep-merge / merge-under type gates (L167, L310)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_deep_merge_list_vs_scalar_replaces() -> None:
    """A list base with a scalar overlay is REPLACED, not concatenated.

    Kills L167 `and->or`: with `or` the scalar string is iterated char-by-char
    and appended to the base list.
    """
    result = _deep_merge_config({"k": [1, 2]}, {"k": "scalar"})
    assert result["k"] == "scalar"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_deep_merge_dict_vs_scalar_replaces() -> None:
    """A dict base with a scalar overlay is REPLACED, not recursed into.

    Kills L165 `and->or`: with `or` it recurses with a str overlay and
    'scalar'.items() raises.
    """
    result = _deep_merge_config({"k": {"a": 1}}, {"k": "scalar"})
    assert result["k"] == "scalar"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_merge_under_dict_vs_scalar_keeps_project() -> None:
    """project dict vs global scalar: project value wins, no recursion.

    Kills L310 `and->or`: with `or` it recurses into the scalar and
    dict('scalar') raises.
    """
    result = _merge_under({"k": {"a": 1}}, {"k": "scalar"})
    assert result["k"] == {"a": 1}


# ---------------------------------------------------------------------------
# YAML default literals (L48, L131)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_agent_config_core_defaults_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`core` defaults to False when the agent config omits it (L48)."""
    cfg_file = tmp_path / "agent.yml"
    cfg_file.write_text("agent: claude\nname: Claude\n", encoding="utf-8")
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_agent_config_path",
        lambda _agent: cfg_file,
    )

    cfg = get_agent_config("claude")
    assert cfg.core is False


# ---------------------------------------------------------------------------
# Project defaults with no global preference (L243, L244)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_defaults_when_unset_and_no_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A project config that omits generic_scanning/mapper knobs gets the defaults.

    Kills L243 (`False->True`: generic_scanning default) and L244
    (`or->and`: mapper `seg or 'legacy'` becomes None).
    """
    _no_global(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text('framework_version: "1.0"\n', encoding="utf-8")

    cfg = get_project_config(project)
    assert cfg.generic_scanning is False
    assert cfg.mapper.segmentation == "legacy"


# ---------------------------------------------------------------------------
# Global inheritance via default kwargs of _apply_globals (L258, L259, L260)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_generic_scanning_inherited_no_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no project config, a global generic_scanning is inherited (L258).

    The `not data` branch calls _apply_globals with default kwargs; flipping
    `has_project_generic_scanning`'s default to True would suppress inheritance.
    """
    _write_global(tmp_path, monkeypatch, "generic_scanning: true\n")
    project = tmp_path / "proj"
    project.mkdir()

    cfg = get_project_config(project)
    assert cfg.generic_scanning is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_segmentation_inherited_no_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no project config, a global segmentation is inherited (L259)."""
    _write_global(tmp_path, monkeypatch, "segmentation: structure-aware\n")
    project = tmp_path / "proj"
    project.mkdir()

    cfg = get_project_config(project)
    assert cfg.mapper.segmentation == "structure-aware"


# ---------------------------------------------------------------------------
# Project wins over global when explicitly set (L281)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_segmentation_wins_over_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Project segmentation is NOT overwritten by a global one (L281 `and->or`)."""
    _write_global(tmp_path, monkeypatch, "segmentation: legacy\n")
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("segmentation: structure-aware\n", encoding="utf-8")

    cfg = get_project_config(project)
    assert cfg.mapper.segmentation == "structure-aware"

"""Config resolution — `~/.reporails/config.yml` ↘ `.ails/config.yml` merge.

Bug 2 (0.5.11): `GlobalConfig` was a 4-field schema (`framework_path`,
`auto_update_check`, `default_agent`, `tier`). Fields like
`disabled_rules` and `exclude_dirs` in `~/.reporails/config.yml` were
silently dropped at parse time, so global defaults had no effect.

The fix:
 1. Extend `GlobalConfig` with project-parity fields.
 2. Read each new field in `get_global_config()`.
 3. Merge globals under per-project values in `get_project_config()`:
    list fields extend, dict fields deep-merge under, project values win.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _patch_reporails_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    """Redirect `~/.reporails` lookups in the loader to `home`."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.REPORAILS_HOME",
        home,
    )


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_disabled_rules_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `disabled_rules` entry in `~/.reporails/config.yml` parses into `GlobalConfig`."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text("disabled_rules:\n  - CORE:D:0001\n", encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)

    from reporails_cli.core.platform.config.config import get_global_config

    cfg = get_global_config()
    assert cfg.disabled_rules == ["CORE:D:0001"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_disabled_rules_merges_into_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Global `disabled_rules` extends project `disabled_rules` (project wins on dup)."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text("disabled_rules:\n  - CORE:G:0001\n", encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text(
        "disabled_rules:\n  - CORE:D:0001\n",
        encoding="utf-8",
    )

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    assert cfg.disabled_rules == ["CORE:D:0001", "CORE:G:0001"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_exclude_dirs_merges_into_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Global `exclude_dirs` extends project list."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text("exclude_dirs: [vendor, node_modules]\n", encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("exclude_dirs: [vendor, dist]\n", encoding="utf-8")

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    assert cfg.exclude_dirs == ["vendor", "dist", "node_modules"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_default_agent_wins_over_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`default_agent: claude` in project beats `default_agent: codex` in global."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text("default_agent: codex\n", encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("default_agent: claude\n", encoding="utf-8")

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    assert cfg.default_agent == "claude"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_generic_scanning_wins_over_global(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Project `generic_scanning: true` overrides global `generic_scanning: false`."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text("generic_scanning: false\n", encoding="utf-8")
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    assert cfg.generic_scanning is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_applies_when_no_project_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty project still picks up global `disabled_rules` and `default_agent`."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text(
        "default_agent: claude\ndisabled_rules:\n  - CORE:G:0001\n",
        encoding="utf-8",
    )
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    project.mkdir()

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    assert cfg.default_agent == "claude"
    assert cfg.disabled_rules == ["CORE:G:0001"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_overrides_dict_merges_under_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Dict fields like `overrides` deep-merge — project wins on the same rule_id."""
    home = tmp_path / ".reporails"
    home.mkdir()
    (home / "config.yml").write_text(
        "overrides:\n  CORE:D:0001:\n    severity: low\n  CORE:G:0002:\n    severity: info\n",
        encoding="utf-8",
    )
    _patch_reporails_home(monkeypatch, home)

    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text(
        "overrides:\n  CORE:D:0001:\n    severity: critical\n",
        encoding="utf-8",
    )

    from reporails_cli.core.platform.config.config import get_project_config

    cfg = get_project_config(project)
    # Project's CORE:D:0001 wins; global's CORE:G:0002 surfaces from the global layer.
    assert cfg.overrides["CORE:D:0001"]["severity"] == "critical"
    assert cfg.overrides["CORE:G:0002"]["severity"] == "info"

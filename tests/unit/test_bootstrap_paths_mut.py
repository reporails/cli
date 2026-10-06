"""Mutation-killing behavioral tests for core/platform/config/bootstrap.py.

Covers the framework-path override guard, the generic-agent config-dir remap,
and the `is_initialized` two-part check. Each assertion reddens the moment the
operator under it flips (verified against the mutation probe).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from reporails_cli.core.platform.config.bootstrap import (
    get_agent_config_path,
    get_framework_root,
    is_initialized,
)
from reporails_cli.core.platform.dto.results import GlobalConfig


# --- get_framework_root: override guard (L87) -----------------------------
@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_framework_root_ignores_nonexistent_override(tmp_path: Path) -> None:
    bad_override = tmp_path / "nope"  # set, but not a real directory
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    with (
        patch(
            "reporails_cli.core.platform.config.config.get_global_config",
            return_value=GlobalConfig(framework_path=bad_override),
        ),
        patch(
            "reporails_cli.core.platform.config.bootstrap.get_bundled_package_root",
            return_value=bundled,
        ),
    ):
        # `and`->`or`: a set-but-missing override would be returned instead of
        # falling through to the bundled root.
        assert get_framework_root() == bundled


# --- get_agent_config_path: generic -> core remap (L112) ------------------
@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_generic_agent_config_lives_in_core(tmp_path: Path) -> None:
    with patch(
        "reporails_cli.core.platform.config.bootstrap.get_rules_path",
        return_value=tmp_path,
    ):
        # `==`->`!=` would route generic to a `generic/` dir instead of `core/`.
        assert get_agent_config_path("generic") == tmp_path / "core" / "config.yml"


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_named_agent_config_lives_in_its_own_dir(tmp_path: Path) -> None:
    with patch(
        "reporails_cli.core.platform.config.bootstrap.get_rules_path",
        return_value=tmp_path,
    ):
        # `==`->`!=` would misroute a named agent into `core/`.
        assert get_agent_config_path("claude") == tmp_path / "claude" / "config.yml"


# --- is_initialized: rules-dir AND core-dir (L227) ------------------------
@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_is_initialized_false_when_core_missing(tmp_path: Path) -> None:
    # rules_path exists but has no core/ subdir.
    with patch(
        "reporails_cli.core.platform.config.bootstrap.get_rules_path",
        return_value=tmp_path,
    ):
        # `and`->`or` would report initialized on the rules dir alone.
        assert is_initialized() is False


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_is_initialized_true_when_core_present(tmp_path: Path) -> None:
    (tmp_path / "core").mkdir()
    with patch(
        "reporails_cli.core.platform.config.bootstrap.get_rules_path",
        return_value=tmp_path,
    ):
        assert is_initialized() is True

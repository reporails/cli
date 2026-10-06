"""Mutation-killing behavioral tests for install-method detection.

Targets the editable-default fall-through survivor in detect_install_method.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from reporails_cli.core.install.self_update import (
    InstallMethod,
    detect_install_method,
)

_SU = "reporails_cli.core.install.self_update"


# --- detect_install_method: editable default -------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_dir_info_without_editable_key_is_not_dev() -> None:
    """direct_url.json with dir_info but no `editable` key must NOT read as DEV.

    Kills: `.get("editable", False) -> .get("editable", True)` (the mutant
    default would treat any dir_info install as editable/DEV).
    """
    mock_dist = MagicMock()
    mock_dist.read_text.side_effect = lambda name: {
        "direct_url.json": json.dumps({"dir_info": {"other": 1}}),
        "INSTALLER": "uv\n",
    }.get(name)
    mock_dist.files = []
    with patch(f"{_SU}.distribution", return_value=mock_dist):
        assert detect_install_method() == InstallMethod.UV

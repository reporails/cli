"""Architecture floor — one interface never imports another.

A module under `interfaces/<a>/` imports nothing from `interfaces/<b>/`: each interface composes `core/` and
`formatters/` on its own, so what two interfaces share lives there. The interfaces are the subfolders of
`interfaces/`, read from the tree; the detector lives once, in `scripts/import_graph.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import import_graph as ig

pytestmark = pytest.mark.architecture


def _plant(tmp_path: Path, files: dict[str, str]) -> Path:
    src = tmp_path / "src" / "reporails_cli"
    for rel, text in files.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return src


def test_no_interface_imports_another() -> None:
    found = ig.interface_cross_reaches()
    assert not found, "an interface imports another interface:\n  " + "\n  ".join(found)


def test_cross_interface_import_fires_in_every_spelling_and_stays_quiet_on_the_clean_ones(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "interfaces/cli/a.py": "from reporails_cli.interfaces.mcp import tools\n",
            "interfaces/cli/b.py": "import reporails_cli.interfaces.mcp.tools\n",
            "interfaces/cli/c.py": "from ..mcp import tools\n",
            "interfaces/cli/d.py": "if TYPE_CHECKING:\n    from reporails_cli.interfaces.mcp import tools\n",
            "interfaces/cli/own.py": "from reporails_cli.interfaces.cli import helpers\n",
            "interfaces/cli/helpers.py": "from reporails_cli.core.pipeline import check_one\n",
            "interfaces/mcp/tools.py": "",
            "interfaces/web/w.py": "from reporails_cli.interfaces.cli import helpers\n",
            "core/pipeline/check_one.py": "",
            "formatters/json.py": "",
        },
    )
    found = ig.interface_cross_reaches(src)
    assert [f.split(" ")[0] for f in found] == [
        "interfaces.cli.a",
        "interfaces.cli.b",
        "interfaces.cli.c",
        "interfaces.cli.d",
        "interfaces.web.w",
    ]


def test_a_new_interface_folder_is_an_outer_node(tmp_path: Path) -> None:
    src = _plant(tmp_path, {"interfaces/cli/a.py": "", "interfaces/zzz/a.py": "", "formatters/json.py": ""})
    assert ig.interface_nodes(src) == {"cli", "zzz"}

"""Architecture floor — layer rows, package cycles and private imports.

Three rules over the import graph of `src/reporails_cli`:

- a module under `core/platform/<layer>/`, or a `core/<subsystem>` with a row, imports only the nodes in its row;
- the `core/` subsystems form no package cycle over runtime imports;
- no package imports a `_private` module or name from another package.
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


def _report(findings: list[str]) -> str:
    return "\n  " + "\n  ".join(findings)


def test_platform_layers_import_only_their_row() -> None:
    found = ig.layer_violations()
    assert not found, f"platform imports outside the layer row:{_report(found)}"


def test_subsystem_row_fires_on_a_heavy_import_and_stays_quiet_on_a_listed_one(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/eventbus/x.py": "from reporails_cli.core.mapper import m\n",
            "core/eventbus/y.py": "from reporails_cli.core.cache import c\n",
            "core/mapper/m.py": "",
            "core/cache/c.py": "",
        },
    )
    found = ig.layer_violations(src)
    assert len(found) == 1
    assert found[0].startswith("core.eventbus.x → core.mapper")


def test_core_subsystems_have_no_package_cycle() -> None:
    found = ig.subsystem_cycles()
    assert not found, f"core subsystem cycles:{_report(found)}"


def test_no_cross_package_private_import() -> None:
    found = ig.private_reaches()
    assert not found, f"cross-package private imports:{_report(found)}"


def test_layer_arm_fires_outside_the_row_and_stays_quiet_inside_it(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/platform/dto/a.py": "from reporails_cli.core.platform.config import b\n",
            "core/platform/config/b.py": "",
            "core/platform/policy/ok.py": "from reporails_cli.core.platform.dto import a\n",
        },
    )
    found = ig.layer_violations(src)
    assert len(found) == 1
    assert found[0].startswith("core.platform.dto.a → core.platform.config.b")


def test_layer_arm_counts_a_type_checking_import(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/platform/dto/a.py": (
                "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from reporails_cli.core.lint import x\n"
            ),
            "core/lint/x.py": "",
        },
    )
    found = ig.layer_violations(src)
    assert len(found) == 1 and found[0].startswith("core.platform.dto.a → core.lint.x")


def test_cycle_arm_fires_on_a_runtime_loop_and_ignores_a_type_checking_back_edge(tmp_path: Path) -> None:
    loop = _plant(
        tmp_path / "loop",
        {
            "core/aa/m.py": "from reporails_cli.core.bb import n\n",
            "core/bb/n.py": "def f():\n    from reporails_cli.core.aa import m\n",
        },
    )
    found = ig.subsystem_cycles(loop)
    assert len(found) == 1 and found[0].startswith("aa ⇄ bb")
    typing_only = _plant(
        tmp_path / "typing",
        {
            "core/aa/m.py": "from reporails_cli.core.bb import n\n",
            "core/bb/n.py": (
                "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from reporails_cli.core.aa import m\n"
            ),
        },
    )
    assert ig.subsystem_cycles(typing_only) == []


def test_private_arm_fires_across_packages_not_within_one(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/aa/_hidden.py": "_SECRET = 1\n",
            "core/aa/same.py": "from ._hidden import _SECRET\n",
            "core/bb/reach.py": "from reporails_cli.core.aa._hidden import _SECRET\n",
            "core/cc/name.py": "from reporails_cli.core.aa.same import _SECRET\n",
        },
    )
    found = ig.private_reaches(src)
    assert len(found) == 2
    assert any(f.startswith("core.bb.reach") for f in found)
    assert any(f.startswith("core.cc.name") for f in found)
    assert not any(f.startswith("core.aa.same") for f in found)


def test_cycle_arm_counts_the_runtime_body_of_a_negated_type_checking_test(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/lint/a.py": (
                "from typing import TYPE_CHECKING\nif not TYPE_CHECKING:\n    from reporails_cli.core.heal import x\n"
            ),
            "core/heal/__init__.py": "from reporails_cli.core.lint import a\n",
            "core/heal/x.py": "",
        },
    )
    found = ig.subsystem_cycles(src)
    assert len(found) == 1 and found[0].startswith("heal ⇄ lint")


def test_cycle_arm_ignores_an_attribute_type_checking_block(tmp_path: Path) -> None:
    src = _plant(
        tmp_path,
        {
            "core/aa/m.py": "from reporails_cli.core.bb import n\n",
            "core/bb/n.py": "import typing\nif typing.TYPE_CHECKING:\n    from reporails_cli.core.aa import m\n",
        },
    )
    assert ig.subsystem_cycles(src) == []

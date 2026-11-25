"""`ails check` reads each rule's `checks.yml` once, however many files the rule's checks run over."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.rules import registry
from reporails_cli.interfaces.cli.main import app


def _count_reads(monkeypatch: pytest.MonkeyPatch) -> Counter[Path]:
    """Count every `read_checks_document` call, through whichever module's name for it a caller holds."""
    reads: Counter[Path] = Counter()
    real = registry.read_checks_document

    def counting(yml_path: Path) -> object:
        reads[yml_path] += 1
        return real(yml_path)

    for module in list(sys.modules.values()):
        if isinstance(module, ModuleType) and getattr(module, "read_checks_document", None) is real:
            monkeypatch.setattr(module, "read_checks_document", counting)
    return reads


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_one_check_run_reads_each_checks_yml_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nRun `uv run pytest` before every commit.\n", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    reads = _count_reads(monkeypatch)

    result = CliRunner().invoke(app, ["check", "--offline", "-f", "json"])

    assert result.exit_code in (0, 1), result.output
    assert reads, "the run read no checks.yml"
    assert max(reads.values()) == 1, {str(p): n for p, n in reads.items() if n > 1}

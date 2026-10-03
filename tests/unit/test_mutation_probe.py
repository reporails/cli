"""Unit tests for scripts/mutation_probe.py — pytest exit-code classification.

`scripts/mutation_probe.py` is a standalone dev-tooling script, not part of the
`reporails_cli` package, so it is loaded via `importlib` from its file path rather
than imported by dotted name.

RED/GREEN story: `run_tests` bucketed ANY
non-zero `pytest` exit code as `"caught"`. pytest exits 4 (usage error, e.g. a
target path that does not exist) and 5 (no tests collected) mean the *invocation*
failed, not that a mutant reddened a real assertion. Before the fix, a typo'd or
renamed target produced a fabricated 100% kill-rate — `KILL-RATE: 2/2 caught` on
a target `does_not_exist.py` that was never actually run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "mutation_probe.py"
_spec = importlib.util.spec_from_file_location("mutation_probe_under_test", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
mutation_probe = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mutation_probe
_spec.loader.exec_module(mutation_probe)


class _FakeCompletedProcess:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


class TestRunTestsExitCodeClassification:
    """`run_tests` must distinguish a broken invocation from a real verdict."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("returncode", [4, 5])
    def test_usage_or_collection_error_is_never_reported_as_caught(self, returncode: int) -> None:
        # Kills the "any non-zero -> caught" bug: exit 4 (usage error, e.g. a
        # nonexistent target) and 5 (no tests collected) must NOT read as a kill.
        with patch.object(mutation_probe.subprocess, "run", return_value=_FakeCompletedProcess(returncode)):
            verdict = mutation_probe.run_tests("tests/unit/does_not_exist.py")
        assert verdict not in ("caught", "survived")
        assert verdict == "error"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_real_test_failure_is_still_caught(self) -> None:
        # Control: a genuine assertion failure (exit 1) is still a kill.
        with patch.object(mutation_probe.subprocess, "run", return_value=_FakeCompletedProcess(1)):
            verdict = mutation_probe.run_tests("tests/unit/some_real_test.py")
        assert verdict == "caught"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_clean_pass_is_survived(self) -> None:
        # Control: exit 0 is still a survivor, not swept into the new error bucket.
        with patch.object(mutation_probe.subprocess, "run", return_value=_FakeCompletedProcess(0)):
            verdict = mutation_probe.run_tests("tests/unit/some_real_test.py")
        assert verdict == "survived"

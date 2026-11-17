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
import json
import subprocess
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


# --- --confirm-kills and --validation-stamp, driven by fake killing commands (no real suite) ---

# A fake killer: exits per `mode` by reading the probed module (mutated when it holds "!=") and
# counting its own calls in files beside it, so a flake can be scripted deterministically.
_FAKE_KILLER = """
import sys
from pathlib import Path

here = Path(__file__).parent
mode = (here / "mode").read_text().strip()
mutated = "!=" in (here / "mod.py").read_text()
key = "mutated" if mutated else "clean"
counter = here / f"{key}.count"
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
if mode == "kills":
    sys.exit(1 if mutated else 0)
if mode == "flake_on_mutant":  # the first mutated run fails, later ones pass
    sys.exit(1 if mutated and n == 0 else 0)
if mode == "red_when_unmutated_rerun":  # green once (validation), then red on a clean tree
    sys.exit(1 if mutated or n > 0 else 0)
sys.exit(0)
"""


@pytest.fixture
def fake_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "mod.py").write_text("def f(a):\n    return a == 1\n")
    (tmp_path / "fake.py").write_text(_FAKE_KILLER)
    (tmp_path / "mode").write_text("kills")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _probe(monkeypatch: pytest.MonkeyPatch, project: Path, *extra: str, command_tail: str = "") -> int:
    command = f"{sys.executable} {project / 'fake.py'}{command_tail}"
    argv = ["mutation_probe.py", str(project / "mod.py"), "--cmd", command, "5", *extra]
    monkeypatch.setattr(sys, "argv", argv)
    return int(mutation_probe.main())


def _json_args(project: Path, *extra: str) -> tuple[str, ...]:
    return ("--json", str(project / "out.json"), *extra)


def _verdicts(project: Path) -> list[str]:
    return [str(r["verdict"]) for r in json.loads((project / "out.json").read_text())]


class TestConfirmKills:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_stable_kill_stays_caught_and_reruns(self, fake_project, monkeypatch, capsys):
        assert _probe(monkeypatch, fake_project, *_json_args(fake_project, "--confirm-kills", "2")) == 0
        assert _verdicts(fake_project) == ["caught"]
        # mutant run + 2 re-runs on the mutant; validation + 1 unmutated confirmation on the clean tree
        assert (fake_project / "mutated.count").read_text() == "3"
        assert (fake_project / "clean.count").read_text() == "2"
        assert "KILL-RATE: 1/1 caught" in capsys.readouterr().out

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_mutant_that_passes_on_rerun_is_flaky(self, fake_project, monkeypatch, capsys):
        (fake_project / "mode").write_text("flake_on_mutant")
        _probe(monkeypatch, fake_project, *_json_args(fake_project, "--confirm-kills", "1"))
        assert _verdicts(fake_project) == ["flaky"]
        out = capsys.readouterr().out
        assert "KILL-RATE: 0/0 caught" in out and "1 flaky" in out
        assert "FLAKY" in out and "2:" in out  # line:col of the `==` token

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unmutated_rerun_that_fails_is_flaky(self, fake_project, monkeypatch):
        (fake_project / "mode").write_text("red_when_unmutated_rerun")
        _probe(monkeypatch, fake_project, *_json_args(fake_project, "--confirm-kills", "1"))
        assert _verdicts(fake_project) == ["flaky"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_without_the_flag_a_flaky_kill_counts_caught(self, fake_project, monkeypatch):
        (fake_project / "mode").write_text("flake_on_mutant")
        _probe(monkeypatch, fake_project, *_json_args(fake_project))
        assert _verdicts(fake_project) == ["caught"]
        assert (fake_project / "mutated.count").read_text() == "1"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_survivor_is_never_rerun(self, fake_project, monkeypatch):
        (fake_project / "mode").write_text("passes")
        _probe(monkeypatch, fake_project, *_json_args(fake_project, "--confirm-kills", "3"))
        assert _verdicts(fake_project) == ["survived"]
        assert (fake_project / "mutated.count").read_text() == "1"


class TestValidationStamp:
    @pytest.fixture
    def repo(self, fake_project: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        for key in ("AUTHOR", "COMMITTER"):
            monkeypatch.setenv(f"GIT_{key}_NAME", "t")
            monkeypatch.setenv(f"GIT_{key}_EMAIL", "t@example.com")
        (fake_project / "other.txt").write_text("x")
        (fake_project / ".gitignore").write_text("*.count\nout.json\nstamp.json\n")
        for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "init"]):
            subprocess.run(["git", *cmd], cwd=fake_project, check=True)
        return fake_project

    def _run(self, monkeypatch, project, capsys, **kw) -> str:
        _probe(monkeypatch, project, "--validation-stamp", str(project / "stamp.json"), **kw)
        return str(capsys.readouterr().out)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_second_probe_skips_validation(self, repo, monkeypatch, capsys):
        assert "validation: RAN" in self._run(monkeypatch, repo, capsys)
        assert (repo / "clean.count").read_text() == "1"
        assert "validation: SKIPPED" in self._run(monkeypatch, repo, capsys)
        assert (repo / "clean.count").read_text() == "1"  # no second validation run
        assert (repo / "mod.py").read_text() == "def f(a):\n    return a == 1\n"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_change_outside_the_module_revalidates(self, repo, monkeypatch, capsys):
        self._run(monkeypatch, repo, capsys)
        (repo / "other.txt").write_text("changed")
        assert "validation: RAN" in self._run(monkeypatch, repo, capsys)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_different_command_revalidates(self, repo, monkeypatch, capsys):
        self._run(monkeypatch, repo, capsys)
        assert "validation: RAN" in self._run(monkeypatch, repo, capsys, command_tail=" extra")

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_new_head_revalidates(self, repo, monkeypatch, capsys):
        self._run(monkeypatch, repo, capsys)
        (repo / "other.txt").write_text("changed")
        subprocess.run(["git", "commit", "-qam", "next"], cwd=repo, check=True)
        assert "validation: RAN" in self._run(monkeypatch, repo, capsys)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_red_validation_writes_no_stamp(self, repo, monkeypatch):
        (repo / "mode").write_text("red_when_unmutated_rerun")
        (repo / "clean.count").write_text("1")  # the clean run is already red
        assert _probe(monkeypatch, repo, "--validation-stamp", str(repo / "stamp.json")) == 1
        assert not (repo / "stamp.json").exists()


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_windows_command_keeps_backslashed_paths_intact() -> None:
    command = r'C:\src\cli\.venv\Scripts\python.exe "C:\my dir\fake.py" -q'
    argv = mutation_probe._split_command(command, windows=True)
    assert argv == [r"C:\src\cli\.venv\Scripts\python.exe", r"C:\my dir\fake.py", "-q"]
    assert mutation_probe._split_command(mutation_probe._join_command(argv, windows=True), windows=True) == argv
    assert mutation_probe._split_command("a 'b c' d", windows=False) == ["a", "b c", "d"]

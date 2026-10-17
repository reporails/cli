"""Guard: the pre-push hook gates the branch being pushed, from a recorded gate pass."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the pre-push hook and the release gates run on the maintainer's POSIX machine",
)

ZERO = "0" * 40
RECORD = "ails-release-gates-passed"


def _git(cwd: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    (root / "scripts").mkdir()
    (root / ".githooks").mkdir()
    shutil.copy(REPO / ".githooks" / "pre-push", root / ".githooks" / "pre-push")
    shutil.copy(REPO / "scripts" / "release-gates.sh", root / "scripts" / "release-gates.sh")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    _git(root, "branch", "0.6.4")
    _git(root, "branch", "feature")
    return root


def _hook(cwd: Path, *lines: str) -> subprocess.CompletedProcess[str]:
    stdin = "".join(line + "\n" for line in lines)
    return subprocess.run(
        ["bash", str(cwd / ".githooks" / "pre-push"), "origin", "git@example.com:x/y.git"],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _push_line(branch: str, sha: str) -> str:
    return f"refs/heads/{branch} {sha} refs/heads/{branch} {ZERO}"


def _record(repo: Path, sha: str) -> None:
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    (common / RECORD).write_text(sha + "\n")


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_recorded_sha_goes_through(repo: Path) -> None:
    sha = _git(repo, "rev-parse", "0.6.4")
    _record(repo, sha)
    assert _hook(repo, _push_line("0.6.4", sha)).returncode == 0


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_different_sha_is_refused(repo: Path) -> None:
    sha = _git(repo, "rev-parse", "0.6.4")
    _record(repo, "1" * 40)
    result = _hook(repo, _push_line("0.6.4", sha))
    assert result.returncode == 1
    assert "release_gates" in result.stderr


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_no_record_is_refused(repo: Path) -> None:
    sha = _git(repo, "rev-parse", "0.6.4")
    result = _hook(repo, _push_line("0.6.4", sha))
    assert result.returncode == 1
    assert "release_gates" in result.stderr


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_other_branch_push_ignores_checked_out_version_branch(repo: Path) -> None:
    _git(repo, "checkout", "-q", "0.6.4")
    sha = _git(repo, "rev-parse", "feature")
    assert _hook(repo, _push_line("feature", sha)).returncode == 0


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_version_branch_push_from_other_checkout_is_gated(repo: Path) -> None:
    _git(repo, "checkout", "-q", "feature")
    sha = _git(repo, "rev-parse", "0.6.4")
    assert _hook(repo, _push_line("0.6.4", sha)).returncode == 1


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_deletion_goes_through(repo: Path) -> None:
    line = f"(delete) {ZERO} refs/heads/0.6.4 {'2' * 40}"
    assert _hook(repo, line).returncode == 0


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_record_is_shared_with_linked_worktree(repo: Path, tmp_path: Path) -> None:
    sha = _git(repo, "rev-parse", "0.6.4")
    _record(repo, sha)
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", str(linked), "feature")
    assert _hook(linked, _push_line("0.6.4", sha)).returncode == 0


@pytest.mark.integration
@pytest.mark.subsys_gates
def test_release_gates_refuses_dirty_tree_before_any_gate(repo: Path) -> None:
    (repo / "dirty.txt").write_text("x\n")
    result = subprocess.run(
        ["bash", "scripts/release-gates.sh"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    assert not (common / RECORD).exists()

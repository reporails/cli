"""The MCP project folder: the agent's `path`, then its first root, then `AILS_PROJECT_DIR`, else a refusal."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.interfaces.mcp.project_folder import NO_PROJECT, ProjectFolder, resolve_project_folder

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


def _ctx(*uris: str, capable: bool = True) -> Any:
    """A tool context whose agent lists `uris` as roots (or declares no roots capability)."""

    async def list_roots() -> Any:
        return SimpleNamespace(roots=[SimpleNamespace(uri=u) for u in uris])

    caps = SimpleNamespace(roots=SimpleNamespace() if capable else None)
    return SimpleNamespace(session=SimpleNamespace(client_capabilities=caps, list_roots=list_roots))


def _resolve(path: str, ctx: Any = None) -> Any:
    return asyncio.run(resolve_project_folder(path, ctx))


@pytest.fixture(autouse=True)
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILS_PROJECT_DIR", raising=False)


def _forbid_working_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> str:
        raise AssertionError("the server's working folder was read")

    monkeypatch.setattr(Path, "cwd", boom)
    monkeypatch.setattr(os, "getcwd", boom)


def test_an_absolute_path_is_the_target(tmp_path: Path) -> None:
    assert _resolve(str(tmp_path)) == ProjectFolder(tmp_path.resolve(), tmp_path.resolve())


def test_a_file_path_without_any_folder_roots_at_its_own_folder(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text("x")
    assert _resolve(str(f)) == ProjectFolder(f.resolve(), tmp_path.resolve())


def test_a_path_wins_over_roots_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in "abc":
        (tmp_path / name).mkdir()
    monkeypatch.setenv("AILS_PROJECT_DIR", str(tmp_path / "c"))
    got = _resolve(str(tmp_path / "a"), _ctx((tmp_path / "b").as_uri()))
    assert got.target == (tmp_path / "a").resolve()


def test_no_path_takes_the_first_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "c").mkdir()
    monkeypatch.setenv("AILS_PROJECT_DIR", str(tmp_path / "c"))
    ctx = _ctx("https://example.com/x", (tmp_path / "b").as_uri(), (tmp_path / "c").as_uri())
    for given in ("", "."):
        assert _resolve(given, ctx) == ProjectFolder((tmp_path / "b").resolve(), (tmp_path / "b").resolve())


def test_root_with_escaped_characters_is_decoded(tmp_path: Path) -> None:
    spaced = tmp_path / "my project"
    spaced.mkdir()
    assert _resolve(".", _ctx(spaced.as_uri())).target == spaced.resolve()


def test_no_path_and_no_roots_takes_the_env_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_PROJECT_DIR", str(tmp_path))
    for ctx in (None, _ctx(), _ctx(capable=False)):
        assert _resolve(".", ctx) == ProjectFolder(tmp_path.resolve(), tmp_path.resolve())


def test_a_relative_path_is_read_against_the_agent_folder(tmp_path: Path) -> None:
    got = _resolve("sub/CLAUDE.md", _ctx(tmp_path.as_uri()))
    assert got == ProjectFolder((tmp_path / "sub" / "CLAUDE.md").resolve(), tmp_path.resolve())


def test_a_relative_path_is_read_against_the_env_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_PROJECT_DIR", str(tmp_path))
    assert _resolve("sub", None).target == (tmp_path / "sub").resolve()


def test_nothing_set_answers_no_project_without_reading_the_working_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_working_folder(monkeypatch)
    for given in ("", ".", "  "):
        assert _resolve(given, _ctx()) == NO_PROJECT
        assert _resolve(given, None) == NO_PROJECT


def test_a_relative_path_with_no_folder_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_working_folder(monkeypatch)
    assert _resolve("docs/CLAUDE.md", _ctx()) == NO_PROJECT
    assert _resolve("docs", None) == NO_PROJECT


def test_a_failing_roots_request_counts_as_no_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fails() -> Any:
        raise RuntimeError("channel closed")

    ctx = _ctx(tmp_path.as_uri())
    ctx.session.list_roots = fails
    assert _resolve(".", ctx) == NO_PROJECT
    monkeypatch.setenv("AILS_PROJECT_DIR", str(tmp_path))
    assert _resolve(".", ctx).target == tmp_path.resolve()


@pytest.mark.parametrize("value", ["${workspaceFolder}", "relative/dir", "   "])
def test_an_env_value_that_is_not_an_absolute_folder_is_no_folder(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_working_folder(monkeypatch)
    monkeypatch.setenv("AILS_PROJECT_DIR", value)
    assert _resolve(".", None) == NO_PROJECT

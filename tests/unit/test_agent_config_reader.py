"""One reader for an agent's config.yml: every reader of it handles a broken file the same way."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from reporails_cli.core.discovery.agent_config import load_config_file_types
from reporails_cli.core.platform.config.claude_settings import _settings_patterns
from reporails_cli.core.platform.config.config import get_agent_config, iter_agent_configs, read_agent_config
from reporails_cli.core.platform.dto.results import AgentConfig

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]

GOOD = (
    "prefix: CLA\nname: Claude\nfile_types:\n  config:\n    scopes:\n"
    "      user:\n        patterns: ['~/.claude/settings.json']\n"
)

BROKEN = [
    pytest.param(b"\xff\xfe\x00bad", "is not UTF-8 text", id="non-utf8"),
    pytest.param(b"a: [1, 2\n", "is not valid YAML (", id="invalid-yaml"),
    pytest.param(b"", "is empty", id="empty"),
    pytest.param(b"- a\n- b\n", "is not a mapping", id="list"),
]


def _write(rules_root: Path, content: bytes) -> Path:
    path = rules_root / "claude" / "config.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _skips(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def _readers(rules_root: Path, path: Path) -> list[tuple[Callable[[], object], object]]:
    """Each of the four readers of the config at `path`, with the value it returns for no config."""

    def _guarded(read: Callable[[], object]) -> Callable[[], object]:
        def _run() -> object:
            with (
                patch("reporails_cli.core.platform.config.claude_settings.get_agent_config_path", return_value=path),
                patch(
                    "reporails_cli.core.discovery.agent_config.get_agent_config_path",
                    return_value=rules_root / "none.yml",
                ),
            ):
                return read()

        return _run

    return [
        (_guarded(lambda: get_agent_config("claude", rules_root)), AgentConfig()),
        (_guarded(lambda: list(iter_agent_configs(rules_root))), []),
        (_guarded(lambda: load_config_file_types("claude", [rules_root])), None),
        (_guarded(_settings_patterns), {}),
    ]


@pytest.mark.parametrize(("content", "problem"), BROKEN)
def test_a_broken_agent_config_is_skipped_with_one_warning_per_reader(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, content: bytes, problem: str
) -> None:
    path = _write(tmp_path, content)
    for read, empty in _readers(tmp_path, path):
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            assert read() == empty
        warnings = _skips(caplog)
        assert len(warnings) == 1, warnings
        assert warnings[0].startswith(f"Skipping agent config {path}: {problem}")


@pytest.mark.parametrize(("content", "problem"), BROKEN)
def test_read_agent_config_returns_none_for_a_broken_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, content: bytes, problem: str
) -> None:
    path = _write(tmp_path, content)
    with caplog.at_level(logging.WARNING):
        assert read_agent_config(path) is None
    assert [m.startswith(f"Skipping agent config {path}: {problem}") for m in _skips(caplog)] == [True]


def test_an_absent_agent_config_logs_nothing(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "claude" / "config.yml"
    with caplog.at_level(logging.DEBUG):
        assert read_agent_config(path) is None
        assert [read() for read, _ in _readers(tmp_path, path)] == [empty for _, empty in _readers(tmp_path, path)]
    assert _skips(caplog) == []


def test_a_good_agent_config_reads_in_every_reader(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = _write(tmp_path, GOOD.encode())
    with caplog.at_level(logging.DEBUG):
        config, configs, file_types, settings = (read() for read, _ in _readers(tmp_path, path))
    assert isinstance(config, AgentConfig)
    assert (config.prefix, config.name) == ("CLA", "Claude")
    assert configs == [(path.parent, read_agent_config(path))]
    assert file_types == {"config": {"scopes": {"user": {"patterns": ["~/.claude/settings.json"]}}}}
    assert settings == {"user": ["~/.claude/settings.json"]}
    assert _skips(caplog) == []

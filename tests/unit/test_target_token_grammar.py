"""Grammar coverage for `ails check` target tokens (`_classify_target_token`).

A bare capability noun (`skills`) targets every instance; `capability:name`
(`skill:backlog`) targets one named instance; everything else is a path. A
leading Windows drive letter (`C:\\...`) must route to path, not be split as
`capability:name`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.interfaces.cli.main import (
    _check_timeout_ceiling,
    _classify_target_token,
    _looks_like_windows_path,
)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "token, expected",
    [
        ("skills", ("capability", ("skills", ""))),
        ("agents", ("capability", ("agents", ""))),
        ("skill:backlog", ("capability", ("skills", "backlog"))),
    ],
    ids=["bare-plural-skills", "bare-plural-agents", "skill-by-name"],
)
def test_capability_tokens(token: str, expected: tuple, tmp_path: Path):
    assert _classify_target_token(token, "claude", tmp_path) == expected


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_bare_noun_needs_sniff_agent(tmp_path: Path):
    """Without a sniffed agent the vocabulary is unknown, so a bare noun is a path."""
    kind, _payload = _classify_target_token("skills", "", tmp_path)
    assert kind == "path"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "token", ["./CLAUDE.md", "README.md", "docs/guide.md"], ids=["dot-path", "bare-file", "subdir-path"]
)
def test_paths_stay_paths(token: str, tmp_path: Path):
    kind, _payload = _classify_target_token(token, "claude", tmp_path)
    assert kind == "path"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "token, is_win",
    [
        ("C:\\Users\\x\\CLAUDE.md", True),
        ("C:/Users/x/CLAUDE.md", True),
        ("C:", True),
        ("skill:backlog", False),
        ("agents", False),
    ],
    ids=["drive-backslash", "drive-forward", "drive-bare", "capability-name", "bare-noun"],
)
def test_windows_drive_letter_guard(token: str, is_win: bool):
    assert _looks_like_windows_path(token) is is_win


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_windows_drive_letter_routes_to_path(tmp_path: Path):
    """A drive-letter token is not mis-split into `capability:name`."""
    kind, _payload = _classify_target_token("C:\\Users\\x\\CLAUDE.md", "claude", tmp_path)
    assert kind == "path"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "token, expected_path",
    [
        ("file:../hub/CLAUDE.md", "../hub/CLAUDE.md"),
        ("file:/home/x/CLAUDE.md", "/home/x/CLAUDE.md"),
        ("file:./CLAUDE.md", "./CLAUDE.md"),
    ],
    ids=["relative", "absolute", "dot-relative"],
)
def test_file_scheme_forces_path(token: str, expected_path: str, tmp_path: Path):
    """`file:<path>` resolves the remainder as a path instead of erroring as an
    unknown capability (was: `capability file is not declared`)."""
    kind, payload = _classify_target_token(token, "claude", tmp_path)
    assert kind == "path"
    assert payload == Path(expected_path).resolve()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_file_scheme_overrides_capability_name(tmp_path: Path):
    """`file:` forces path even when the remainder collides with a capability noun."""
    kind, payload = _classify_target_token("file:skills", "claude", tmp_path)
    assert kind == "path"
    assert payload == Path("skills").resolve()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_timeout_ceiling_default_and_overrides(monkeypatch):
    monkeypatch.delenv("AILS_CHECK_TIMEOUT_S", raising=False)
    assert _check_timeout_ceiling() == 600
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "30")
    assert _check_timeout_ceiling() == 30
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "0")  # disabled
    assert _check_timeout_ceiling() == 0
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "not-a-number")  # falls back to default
    assert _check_timeout_ceiling() == 600

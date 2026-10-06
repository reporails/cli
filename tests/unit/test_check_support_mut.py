"""Mutation-killing behavioral tests for `check_support` helpers.

Targets survivors in `_serialize_match`, `_resolve_rule_token`,
`_generic_scan_file_types`, and `_arm_check_timeout`.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch
from reporails_cli.interfaces.cli.check_support import (
    _arm_check_timeout,
    _generic_scan_file_types,
    _resolve_rule_token,
    _serialize_match,
)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_serialize_match_none_returns_empty() -> None:
    # Kills L44 `is -> is not`: a None match must short-circuit to {}.
    assert _serialize_match(None) == {}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_serialize_match_populated_carries_properties() -> None:
    # Kills L44 `is -> is not`: a populated match must NOT return {} early.
    match = FileMatch(type="context", format="md", scope="repo")
    result = _serialize_match(match)
    assert result["type"] == "context"
    assert result["format"] == "md"
    assert result["scope"] == "repo"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resolve_rule_token_maps_slug_to_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kills L142 `== -> !=`: a matching slug must resolve to that rule's id.
    fake_rule = SimpleNamespace(slug="my-slug", id="CORE:0001")
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.rules_query.load_all_rules",
        lambda: [fake_rule],
    )
    assert _resolve_rule_token("my-slug") == "CORE:0001"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resolve_rule_token_unknown_slug_returns_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Companion: a non-matching slug falls through to the raw token.
    fake_rule = SimpleNamespace(slug="my-slug", id="CORE:0001")
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.rules_query.load_all_rules",
        lambda: [fake_rule],
    )
    assert _resolve_rule_token("other-slug") == "other-slug"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_generic_scan_passes_scanning_true(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kills L120 `True -> False`: classify_files must receive generic_scanning=True.
    captured: dict[str, object] = {}

    def fake_classify(scan_root: Path, files: list[Path], file_types: list[object], generic_scanning: bool = False):
        captured["generic_scanning"] = generic_scanning
        return []

    monkeypatch.setattr("reporails_cli.core.classify.classify_files", fake_classify)
    monkeypatch.setattr("reporails_cli.core.classify.load_file_types", lambda agent, project_root: [])
    _generic_scan_file_types(Path("/proj"), [], "claude", True)
    assert captured["generic_scanning"] is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_generic_scan_import_extra_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kills L130 `== -> !=` and `and -> or`: only UNSEEN generic files enter import_extra.
    target = Path("/proj")
    instruction_files = [target / "A.md"]  # already seen
    classified = [
        ClassifiedFile(path=target / "A.md", file_type="generic"),  # generic but seen -> excluded
        ClassifiedFile(path=target / "B.md", file_type="generic"),  # generic + unseen -> included
        ClassifiedFile(path=target / "C.md", file_type="referenced"),  # not generic -> excluded
    ]
    monkeypatch.setattr(
        "reporails_cli.core.classify.classify_files",
        lambda scan_root, files, file_types, generic_scanning=False: classified,
    )
    monkeypatch.setattr("reporails_cli.core.classify.load_file_types", lambda agent, project_root: [])

    import_extra, _ft_by_path = _generic_scan_file_types(target, instruction_files, "claude", True)

    assert (target / "B.md") in import_extra
    assert (target / "A.md") not in import_extra
    assert (target / "C.md") not in import_extra


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="SIGALRM backstop is POSIX-only")
def test_arm_check_timeout_installs_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kills L164 `== -> !=`: on POSIX the SIGALRM handler must actually be installed.
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "600")
    original = signal.getsignal(signal.SIGALRM)
    try:
        _arm_check_timeout()
        installed = signal.getsignal(signal.SIGALRM)
        assert installed is not original
        assert callable(installed)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="SIGALRM backstop is POSIX-only")
def test_arm_check_timeout_noop_when_ceiling_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    # Kills L167 `<= -> <`: a ceiling of 0 must disable the backstop (no handler installed).
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "0")
    original = signal.getsignal(signal.SIGALRM)
    try:
        _arm_check_timeout()
        assert signal.getsignal(signal.SIGALRM) is original
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)

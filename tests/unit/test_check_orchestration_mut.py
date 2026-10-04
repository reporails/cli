"""Mutation-closing behavioral tests for check_orchestration.py.

Each test reddens when a specific operator mutation is reintroduced into the
source (verified with scripts/mutation_probe.py). Scope is LOCAL orchestration
behavior: token classification, capability-path resolution, output dispatch,
the heal-pass gating flag, stage-timing gate, and strict-exit policy.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.classify import capability_paths as cap_paths
from reporails_cli.core.classify import focus_expansion as focus_mod
from reporails_cli.core.platform.config import vocabulary as vocab_mod
from reporails_cli.core.platform.dto.lexicon import CapabilityVocabulary
from reporails_cli.interfaces.cli import check_orchestration as orch

# --- L89: _looks_like_windows_path (chained `and`) ---


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("C:\\Users\\x", True),
        ("C:/Users/x", True),
        ("C:", True),
        ("skill:backlog", False),  # alpha + ":" but 3rd char not a slash
        ("a", False),  # too short
        ("1:foo", False),  # leading char not alpha
        ("skills", False),  # no colon
    ],
)
def test_looks_like_windows_path(token, expected):
    assert cap_paths.looks_like_windows_path(token) is expected


# --- L154/L157: _file_under_target ---


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_file_target_matches_exact_file(tmp_path):
    """A file target must match the identical file path (L154 == guard)."""
    tgt = tmp_path / "x.md"
    tgt.write_text("hi", encoding="utf-8")
    assert orch._file_under_target(tgt, tgt) is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_file_target_rejects_other_file(tmp_path):
    tgt = tmp_path / "x.md"
    tgt.write_text("hi", encoding="utf-8")
    other = tmp_path / "y.md"
    other.write_text("hi", encoding="utf-8")
    assert orch._file_under_target(other, tgt) is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_nonexistent_target_returns_false(tmp_path):
    """A target that is neither file nor dir must return False (L157)."""
    ghost = tmp_path / "does_not_exist"
    f = tmp_path / "f.md"
    f.write_text("hi", encoding="utf-8")
    assert orch._file_under_target(f, ghost) is False


# --- L189/L192/L194: _capability_declared ---


def _patch_vocab(monkeypatch, *, virtual=None, fold=None, decls=None):
    vocab = CapabilityVocabulary(virtual=list(virtual or []), fold=dict(fold or {}))
    monkeypatch.setattr(vocab_mod, "load_capability_vocabulary", lambda: vocab)
    monkeypatch.setattr(cap_paths, "load_capability_vocabulary", lambda: vocab)
    monkeypatch.setattr(cap_paths, "available_capabilities", lambda agent, project_root=None: list(decls or []))


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_virtual_capability_is_declared(monkeypatch, tmp_path):
    """A virtual capability must be declared (L189 `return True`)."""
    _patch_vocab(monkeypatch, virtual=["referenced"], decls=[])
    assert cap_paths.capability_declared("referenced", "claude", tmp_path) is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_config_declared_capability(monkeypatch, tmp_path):
    """A capability present in the agent's decls is declared (L192 `return True`)."""
    _patch_vocab(monkeypatch, decls=["rules"])
    assert cap_paths.capability_declared("rules", "claude", tmp_path) is True


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_fold_without_declared_member_is_not_declared(monkeypatch, tmp_path):
    """A fold whose members are NOT in decls must NOT declare (L194 `and`)."""
    _patch_vocab(monkeypatch, fold={"agent": ["agents"]}, decls=["other"])
    assert cap_paths.capability_declared("agent", "claude", tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_fold_with_declared_member_is_declared(monkeypatch, tmp_path):
    _patch_vocab(monkeypatch, fold={"agent": ["agents"]}, decls=["agents"])
    assert cap_paths.capability_declared("agent", "claude", tmp_path) is True


# --- L298: _should_exit_strict short-circuit ---


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_should_exit_strict_false_when_not_strict(tmp_path):
    """Not-strict must always be False (L298 `return False`)."""
    result = SimpleNamespace(findings=[SimpleNamespace(file="a.md")])
    assert orch._should_exit_strict(False, set(), tmp_path, result) is False


# --- L253: _emit_stage_timing gate ---


class _FakeTimer:
    def __init__(self, enabled, records):
        self.enabled = enabled
        self.records = records

    def render_lines(self):
        return ["timing 1ms"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stage_timing_silent_for_json(monkeypatch):
    """JSON format must never print stage timing (L253 `==` + first `or`)."""
    calls = []
    monkeypatch.setattr(orch.console, "print", lambda *a, **k: calls.append(a))
    orch._emit_stage_timing(_FakeTimer(enabled=True, records=[1]), "json")
    assert calls == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stage_timing_silent_when_no_records(monkeypatch):
    """No records must suppress output (L253 second `or`)."""
    calls = []
    monkeypatch.setattr(orch.console, "print", lambda *a, **k: calls.append(a))
    orch._emit_stage_timing(_FakeTimer(enabled=True, records=[]), "text")
    assert calls == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stage_timing_prints_when_enabled_text_with_records(monkeypatch):
    calls = []
    monkeypatch.setattr(orch.console, "print", lambda *a, **k: calls.append(a))
    orch._emit_stage_timing(_FakeTimer(enabled=True, records=[1]), "text")
    assert calls  # rendered


# --- L216/L230: _dispatch_output routing ---


def _patch_dispatch(monkeypatch):
    text_calls = []
    monkeypatch.setattr(orch, "print_text_result", lambda *a, **k: text_calls.append(a))
    import reporails_cli.formatters.github as gh
    import reporails_cli.formatters.json as jf

    monkeypatch.setattr(jf, "format_combined_result", lambda *a, **k: {"ok": 1})
    monkeypatch.setattr(gh, "format_combined_annotations", lambda *a, **k: "GHANNOT")
    return text_calls


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_dispatch_json_prints_json_not_text(monkeypatch, capsys, tmp_path):
    """output_format 'json' must route to JSON, not text (L216 `==`)."""
    text_calls = _patch_dispatch(monkeypatch)
    orch._dispatch_output("json", object(), object(), 1.0, set(), tmp_path, False, False, None)
    out = capsys.readouterr().out
    assert '"ok"' in out
    assert text_calls == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_dispatch_github_prints_annotations_not_text(monkeypatch, capsys, tmp_path):
    """output_format 'github' must route to GitHub, not text (L230 `==`)."""
    text_calls = _patch_dispatch(monkeypatch)
    orch._dispatch_output("github", object(), object(), 1.0, set(), tmp_path, False, False, None)
    out = capsys.readouterr().out
    assert "GHANNOT" in out
    assert text_calls == []


# --- L51/L64: _resolve_capability_paths_one ---


def _patch_resolve(monkeypatch, *, resolved, expand_ret):
    monkeypatch.setattr(cap_paths, "capability_declared", lambda *a, **k: True)
    monkeypatch.setattr(cap_paths, "resolve_capability", lambda *a, **k: resolved)
    monkeypatch.setattr(cap_paths, "list_capability_targets", lambda *a, **k: [])
    monkeypatch.setattr(focus_mod, "expand_focus", lambda *a, **k: expand_ret)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resolved_capability_returns_paths(monkeypatch, tmp_path):
    """A non-None resolution must return its path, not raise (L51 `is None`)."""
    p = tmp_path / "skill.md"
    _patch_resolve(monkeypatch, resolved=p, expand_ret=({p}, ["u"]))
    paths, unresolved = orch._resolve_capability_paths_one("skills", "foo", "claude", tmp_path)
    assert paths == {p}
    assert unresolved == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_agents_capability_triggers_focus_expansion(monkeypatch, tmp_path):
    """Only 'agents' expands focus (L64 `==`)."""
    p = tmp_path / "agent.md"
    _patch_resolve(monkeypatch, resolved=p, expand_ret=({p}, ["unresolved-skill"]))
    _paths, unresolved = orch._resolve_capability_paths_one("agents", "foo", "claude", tmp_path)
    assert unresolved == ["unresolved-skill"]


# --- L119: _classify_target_token capability-keyword guard ---


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_no_sniff_agent_token_is_path(monkeypatch, tmp_path):
    """With no sniff agent, a bare noun must classify as a path (L119 `and`).

    The `and -> or` mutant would consult is_capability_keyword despite the
    empty agent and mis-route the token to a capability.
    """
    monkeypatch.setattr(cap_paths, "is_capability_keyword", lambda *a, **k: True)
    monkeypatch.setattr(cap_paths, "canonicalize_capability", lambda *a, **k: "skills")
    kind, _payload = cap_paths.classify_target_token("skills", "", tmp_path)
    assert kind == "path"


# --- L45: not-declared error message fallback ---


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_undeclared_capability_message_shows_none(monkeypatch, tmp_path):
    """The 'Available:' line must read '(none)' when there are no capabilities.

    Normal `join(...) or '(none)'` -> '(none)'; the `or -> and` mutant yields
    an empty string, dropping the '(none)' marker.
    """
    import typer

    printed = []
    monkeypatch.setattr(cap_paths, "capability_declared", lambda *a, **k: False)
    monkeypatch.setattr(cap_paths, "available_capabilities", lambda *a, **k: [])
    monkeypatch.setattr(orch.console, "print", lambda *a, **k: printed.append(str(a)))
    with pytest.raises(typer.Exit):
        orch._resolve_capability_paths_one("skills", "foo", "claude", tmp_path)
    assert any("(none)" in msg for msg in printed)


# --- L276: heal-pass show flag ---


def _run_heal_capture(monkeypatch, *, isatty, output_format):
    captured = {}
    import reporails_cli.core.lint.suppression as supp
    import reporails_cli.interfaces.cli.heal as heal

    def _fake_mech(ruleset_map, target, dry_run, show, console, files, suppressed):
        captured["show"] = show
        return []

    monkeypatch.setattr(supp, "suppressed_lines", lambda *a, **k: {})
    monkeypatch.setattr(heal, "_apply_mechanical_fixes", _fake_mech)
    monkeypatch.setattr(heal, "_collect_section_suggestions", lambda *a, **k: [])
    monkeypatch.setattr(heal, "_output_heal_results", lambda *a, **k: None)
    monkeypatch.setattr(orch.sys.stdout, "isatty", lambda: isatty, raising=False)
    orch._run_heal_pass(Path("."), [], object(), "claude", True, output_format)
    return captured["show"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_show_false_when_not_tty(monkeypatch):
    """No TTY => show is False regardless of format (L276 `and`)."""
    assert _run_heal_capture(monkeypatch, isatty=False, output_format="text") is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_show_false_for_json_even_on_tty(monkeypatch):
    """JSON output => show is False even on a TTY (L276 `!=`)."""
    assert _run_heal_capture(monkeypatch, isatty=True, output_format="json") is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_show_true_on_tty_text(monkeypatch):
    assert _run_heal_capture(monkeypatch, isatty=True, output_format="text") is True

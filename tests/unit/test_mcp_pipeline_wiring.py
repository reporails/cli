"""Unit-level wiring tests for the MCP tool shell's parity fixes (findings 3, 4, 5).

These pin the WIRING -- the right value reaches the right callee -- with everything else
mocked, so they run fast and need neither the bundled ONNX model nor the rules framework.
Project-level equivalence (the actual finding sets matching the CLI byte-for-byte) is
covered by `tests/integration/test_mcp_cli_equivalence.py`.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.interfaces.mcp import tools, validate_targets

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


# ---------------------------------------------------------------------------
# `scoped` must reach `run_m_probes` so a single-file validate
# skips project-aggregate mechanical checks, matching `ails check <file>`.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("scoped", [True, False])
def test_run_local_checks_threads_scoped_into_m_probes(monkeypatch, scoped):
    captured = {}
    monkeypatch.setattr(
        "reporails_cli.core.lint.rule_runner.run_m_probes",
        lambda *_a, **kw: captured.update(kw) or [],
    )

    tools._checks_over_pairs(Path("/proj"), [("claude", [Path("/proj/CLAUDE.md")])], None, scoped)

    assert captured.get("scoped") is scoped


@pytest.mark.unit
@pytest.mark.subsys_server
def test_run_pipeline_scopes_a_single_file_target(monkeypatch, tmp_path):
    """`_run_pipeline` on a file target must run the mechanical probes `scoped=True`,
    while a directory target (below) runs them unscoped."""
    captured = {}
    single_file = tmp_path / "CLAUDE.md"
    single_file.write_text("# Claude\n", encoding="utf-8")

    monkeypatch.setattr(
        "reporails_cli.interfaces.mcp.tools._discover_files",
        lambda _target, single_file=None: ([], "claude", [single_file], {}),
    )
    monkeypatch.setattr("reporails_cli.interfaces.mcp.tools._build_map", lambda *_a, **_k: (None, None))
    monkeypatch.setattr(
        "reporails_cli.core.lint.rule_runner.run_m_probes",
        lambda *_a, **kw: captured.update(kw) or [],
    )
    monkeypatch.setattr(
        "reporails_cli.interfaces.mcp.tools._assemble_mcp_result",
        lambda *_a, **_k: (SimpleNamespace(hooks=()), None),
    )
    monkeypatch.setattr("reporails_cli.formatters.json.format_combined_result", lambda *_a, **_k: {"files": {}})

    tools._run_pipeline(single_file, full=True)

    assert captured.get("scoped") is True


@pytest.mark.unit
@pytest.mark.subsys_server
def test_run_pipeline_does_not_scope_a_directory_target(monkeypatch, tmp_path):
    captured = {}
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text("# Claude\n", encoding="utf-8")

    monkeypatch.setattr(
        "reporails_cli.interfaces.mcp.tools._discover_files",
        lambda _target, single_file=None: ([], "claude", [claude_md], {}),
    )
    monkeypatch.setattr("reporails_cli.interfaces.mcp.tools._build_map", lambda *_a, **_k: (None, None))
    monkeypatch.setattr(
        "reporails_cli.core.lint.rule_runner.run_m_probes",
        lambda *_a, **kw: captured.update(kw) or [],
    )
    monkeypatch.setattr(
        "reporails_cli.interfaces.mcp.tools._assemble_mcp_result",
        lambda *_a, **_k: (SimpleNamespace(hooks=()), None),
    )
    monkeypatch.setattr("reporails_cli.formatters.json.format_combined_result", lambda *_a, **_k: {"files": {}})

    tools._run_pipeline(tmp_path, full=True)

    assert captured.get("scoped") is False


# ---------------------------------------------------------------------------
# A single-file `validate` target must root at the
# real project root (CLI parity), not `target.parent`.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_resolve_scan_target_roots_a_nested_file_at_the_project_root(tmp_path):
    (tmp_path / ".git").mkdir()
    rules_dir = tmp_path / ".claude" / "rules"
    rules_dir.mkdir(parents=True)
    target = rules_dir / "style.md"
    target.write_text("# Style\n", encoding="utf-8")

    scan_root, single_file = tools._resolve_scan_target(target)

    assert scan_root == tmp_path
    assert single_file == target


@pytest.mark.unit
@pytest.mark.subsys_server
def test_resolve_scan_target_directory_still_roots_at_itself(tmp_path):
    """A directory target keeps CLI parity via `resolve_project_root` — unaffected by
    the file-target fix above."""
    scan_root, single_file = tools._resolve_scan_target(tmp_path)

    assert scan_root == tmp_path
    assert single_file is None


# ---------------------------------------------------------------------------
# A server funnel rejection must reach the payload as a top-level
# `funnel` object. `offline` is never recomputed here: whether the rejection
# carries a real HTTP status or not, no diagnostics report was produced, which
# is the one condition that already decided `offline` upstream.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_attach_funnel_carries_the_rejection_without_touching_offline():
    """A parsed rejection (a real HTTP status, e.g. a rate limit) still leaves `offline`
    exactly as the caller already set it -- a rejection with a status is not a
    diagnostics report, so it is still an offline run."""
    from reporails_cli.core.platform.dto.diagnostics import FunnelError

    err = FunnelError(
        error="rate_limit_exceeded", tier="free", reset_in=30, upgrade_url="https://x/upgrade", status=429
    )
    payload = {"offline": True, "files": {}}

    out = tools._attach_funnel(payload, err)

    assert out["offline"] is True
    assert out["funnel"]["error"] == "rate_limit_exceeded"
    assert out["funnel"]["upgrade_url"] == "https://x/upgrade"
    assert out["funnel"]["message"]
    assert out["funnel"]["status"] == 429
    assert out["funnel"]["tier"] == "free"
    assert out["server_error"]["error"] == "rate_limit_exceeded"


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("error_token", ["timeout", "network_error", "malformed_response", "http_error"])
def test_attach_funnel_keeps_offline_true_for_a_transport_failure(error_token):
    """A transport failure (no diagnostics report, `status` unset on most tokens) also
    leaves `offline` untouched -- no diagnostics report reached this payload either way,
    so a dead port and a parsed rejection must not disagree on `offline`."""
    from reporails_cli.core.platform.dto.diagnostics import FunnelError

    err = FunnelError(error=error_token, message="Could not reach the diagnostics server")
    payload = {"offline": True, "files": {}}

    out = tools._attach_funnel(payload, err)

    assert out["offline"] is True
    # The reason must still be visible -- an outage is not silently swallowed.
    assert out["funnel"]["error"] == error_token
    assert out["server_error"]["error"] == error_token


@pytest.mark.unit
@pytest.mark.subsys_server
def test_attach_funnel_never_recomputes_offline_from_the_rejection():
    """`_attach_funnel` must not derive `offline` from the rejection at all -- it only adds
    `server_error` / `funnel` and leaves whatever `offline` the caller already computed
    (from whether a diagnostics report came back) exactly as given, on a rejection that
    does carry a real HTTP status."""
    from reporails_cli.core.platform.dto.diagnostics import FunnelError

    err = FunnelError(error="http_error", status=404, message="Diagnostics server returned HTTP 404")
    payload = {"offline": False, "files": {}}

    out = tools._attach_funnel(payload, err)

    assert out["offline"] is False
    assert out["funnel"]["status"] == 404


@pytest.mark.unit
@pytest.mark.subsys_server
def test_attach_funnel_message_has_no_rich_markup():
    """The MCP payload's `funnel.message` must be plain text — the agent on the other end of
    stdio has no Rich renderer. Before the fix, `_attach_funnel` rendered the message through
    `formatters.text.funnel_cta.format_cta`, the TERMINAL CTA renderer, which appends
    `-> [link=...][bold]<label>[/bold][/link]` for the conversion arrow; a paying user hitting
    a rate limit saw those literal bracket tags in their agent's chat.
    `upgrade_url` already carries the link structurally, so the message only needs the prose half."""
    from reporails_cli.core.platform.dto.diagnostics import FunnelError

    err = FunnelError(error="rate_limit_exceeded", tier="free", reset_in=30, upgrade_url="https://x/upgrade")
    payload = {"offline": True, "files": {}}

    out = tools._attach_funnel(payload, err)

    message = out["funnel"]["message"]
    assert "[link=" not in message
    assert "[bold]" not in message
    assert "[/bold]" not in message
    assert "[/link]" not in message


@pytest.mark.unit
@pytest.mark.subsys_server
def test_attach_funnel_is_a_no_op_without_a_funnel_error():
    payload = {"offline": True, "files": {}}
    assert tools._attach_funnel(payload, None) == payload
    assert tools._attach_funnel(payload, object()) == payload


@pytest.mark.unit
@pytest.mark.subsys_server
def test_assemble_mcp_result_surfaces_the_funnel_error(monkeypatch, tmp_path):
    """`_assemble_mcp_result` must return the response's `funnel_error` alongside the result,
    not drop it the way `_server_lint` used to when it returned only `.result`."""
    from reporails_cli.core.platform.dto.diagnostics import FunnelError, LintResponse

    err = FunnelError(error="project_limit_reached", tier="pro")
    monkeypatch.setattr(
        "reporails_cli.interfaces.mcp.tools._server_lint",
        lambda *_a, **_k: LintResponse(result=None, funnel_error=err),
    )

    _result, funnel_error = tools._assemble_mcp_result(tmp_path, "claude", [], ruleset_map=None, local=([], [], []))

    assert funnel_error is err


# ---------------------------------------------------------------------------
# The generic-scan fold must reach `_discover_files`: an
# `@`-import-reached file is added to the scored set and classified.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_discover_files_folds_generic_scanned_imports(monkeypatch, tmp_path):
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text("# Claude\n", encoding="utf-8")
    arch = tmp_path / "docs" / "arch.md"

    monkeypatch.setattr(
        "reporails_cli.core.platform.config.config.get_project_config",
        lambda _t: SimpleNamespace(default_agent="", exclude_dirs=[], exclude_files=[], generic_scanning=True),
    )
    monkeypatch.setattr("reporails_cli.core.discovery.agents.detect_agents", lambda _t: [])
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping.resolve_agent_filters",
        lambda *_a, **_k: ("claude", False, False, ["AGENT"]),
    )
    monkeypatch.setattr(
        "reporails_cli.core.discovery.agents.get_all_scannable_files",
        lambda _t, agents=None: [claude_md],
    )
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping.apply_generic_scan",
        lambda *_a, **_k: ([arch], {"docs/arch.md": "generic"}),
    )

    result = tools._discover_files(tmp_path)

    assert not isinstance(result, dict), result
    _filter_agents, _agent, files, file_type_by_path = result
    assert claude_md in files
    assert arch in files
    assert file_type_by_path == {"docs/arch.md": "generic"}


@pytest.mark.unit
@pytest.mark.subsys_server
def test_discover_files_skips_generic_scan_fold_when_disabled(monkeypatch, tmp_path):
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text("# Claude\n", encoding="utf-8")

    monkeypatch.setattr(
        "reporails_cli.core.platform.config.config.get_project_config",
        lambda _t: SimpleNamespace(default_agent="", exclude_dirs=[], exclude_files=[], generic_scanning=False),
    )
    monkeypatch.setattr("reporails_cli.core.discovery.agents.detect_agents", lambda _t: [])
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping.resolve_agent_filters",
        lambda *_a, **_k: ("claude", False, False, ["AGENT"]),
    )
    monkeypatch.setattr(
        "reporails_cli.core.discovery.agents.get_all_scannable_files",
        lambda _t, agents=None: [claude_md],
    )

    result = tools._discover_files(tmp_path)

    assert not isinstance(result, dict), result
    _filter_agents, _agent, files, file_type_by_path = result
    assert files == [claude_md]
    assert file_type_by_path == {}


# ---------------------------------------------------------------------------
# `keep_target_locations` -- a targeted `validate` reply must narrow `files`
# and `cross_file` to the targeted paths too, not just `workflow.locations`.
# ---------------------------------------------------------------------------


def _target_payload(with_workflow: bool = True) -> dict:
    payload: dict = {
        "quality": 72.5,
        "level": "L2",
        "stats": {"total": 2},
        "surface_health": [{"name": "skills", "score": 4}],
        "files": {
            "skills/target/SKILL.md": {"findings": [{"rule": "CORE:S:0001"}], "count": 1},
            "skills/other/SKILL.md": {"findings": [{"rule": "CORE:S:0002"}], "count": 1},
        },
        "cross_file": [
            {"file_1": "skills/target/SKILL.md", "file_2": "CLAUDE.md", "line_1": 1, "line_2": 2, "type": "overlap"},
            {
                "file_1": "skills/other/SKILL.md",
                "file_2": "docs/other.md",
                "line_1": 3,
                "line_2": 4,
                "type": "overlap",
            },
        ],
        "cross_file_coordinates": [
            {"file_1": "skills/target/SKILL.md", "file_2": "CLAUDE.md", "type": "overlap", "count": 2},
            {"file_1": "skills/other/SKILL.md", "file_2": "docs/other.md", "type": "overlap", "count": 5},
        ],
        "pro": {"count": 7, "errors": 3, "warnings": 4},
    }
    if with_workflow:
        payload["workflow"] = {
            "summary": "s",
            "listed": [{"rule": "CORE:E:0004", "reason": "long", "count": 40}],
            "locations": [
                {"order": 1, "kind": "skills", "files": ["skills/target/SKILL.md"]},
                {"order": 2, "kind": "skills", "files": ["skills/other/SKILL.md"]},
            ],
        }
    return payload


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_narrows_files_and_cross_file(tmp_path):
    """`files` keeps only the targeted path's entry, and `cross_file` keeps only the entry
    that touches it -- the pair between two untargeted files is dropped."""
    payload = _target_payload()
    target_file = tmp_path / "skills" / "target" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:target",))

    assert set(out["files"]) == {"skills/target/SKILL.md"}
    assert out["cross_file"] == [payload["cross_file"][0]]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_narrows_files_and_cross_file_without_workflow(tmp_path):
    """The same narrowing applies with no `workflow` key at all (a free-tier targeted
    reply) -- `keep_target_locations` must not require `workflow` to narrow `files` /
    `cross_file`."""
    payload = _target_payload(with_workflow=False)
    target_file = tmp_path / "skills" / "target" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:target",))

    assert set(out["files"]) == {"skills/target/SKILL.md"}
    assert out["cross_file"] == [payload["cross_file"][0]]
    assert "workflow" not in out


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_leaves_untargeted_keys_whole(tmp_path):
    """`stats`, `quality`, and `workflow.listed` are untargeted -- they stay exactly as
    given, and the surviving location is renumbered from 1."""
    payload = _target_payload()
    target_file = tmp_path / "skills" / "target" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:target",))

    assert out["stats"] == payload["stats"]
    assert out["quality"] == payload["quality"]
    assert out["workflow"]["listed"] == payload["workflow"]["listed"]
    assert [loc["order"] for loc in out["workflow"]["locations"]] == [1]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_narrows_cross_file_coordinates(tmp_path):
    """`cross_file_coordinates` is narrowed the same way as `cross_file` -- only the pair
    that touches the targeted path survives, the pair between two untargeted files is
    dropped."""
    payload = _target_payload()
    target_file = tmp_path / "skills" / "target" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:target",))

    assert out["cross_file_coordinates"] == [payload["cross_file_coordinates"][0]]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_leaves_the_aggregate_pro_block_whole(tmp_path):
    """`pro` carries only whole-project aggregate counts (no per-file/per-pair breakdown), so
    it stays untouched by targeting, same as `stats` and `quality`."""
    payload = _target_payload()
    target_file = tmp_path / "skills" / "target" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:target",))

    assert out["pro"] == payload["pro"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_keep_target_locations_keeps_kept_locations_other_files(tmp_path):
    """A kept location's `files` cover more than the targeted path (`skills:<name>` resolves
    only to `SKILL.md`, but the location's own `files` also list its supporting files). The
    narrowed reply must keep every one of the kept location's files, and `cross_file` /
    `cross_file_coordinates` entries touching them, not just the entry naming the targeted
    path itself."""
    payload = {
        "files": {
            "a/SKILL.md": {"findings": [], "count": 0},
            "a/ref.md": {"findings": [], "count": 0},
            "b.md": {"findings": [], "count": 0},
        },
        "cross_file": [
            {"file_1": "a/ref.md", "file_2": "c.md", "line_1": 1, "line_2": 2, "type": "overlap"},
            {"file_1": "b.md", "file_2": "c.md", "line_1": 3, "line_2": 4, "type": "overlap"},
        ],
        "cross_file_coordinates": [
            {"file_1": "a/ref.md", "file_2": "c.md", "type": "overlap", "count": 1},
            {"file_1": "b.md", "file_2": "c.md", "type": "overlap", "count": 1},
        ],
        "workflow": {
            "summary": "s",
            "listed": [],
            "locations": [{"order": 1, "kind": "skills", "files": ["a/SKILL.md", "a/ref.md"]}],
        },
    }
    target_file = tmp_path / "a" / "SKILL.md"

    out = validate_targets.keep_target_locations(payload, {target_file}, set(), tmp_path, ("skills:a",))

    assert set(out["files"]) == {"a/SKILL.md", "a/ref.md"}
    assert out["cross_file"] == [payload["cross_file"][0]]
    assert out["cross_file_coordinates"] == [payload["cross_file_coordinates"][0]]

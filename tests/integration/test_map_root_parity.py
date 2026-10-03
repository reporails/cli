"""In-process vs daemon parity for the shared map builder, on the real mapper.

`map_instruction_files` has two arms: the daemon round-trip and the in-process fallback.
The daemon arm sends the project root on the wire and the daemon-side handler maps against
it; the in-process arm ran without one, so it fell back to "the first file's own parent" and
every nested agent surface (`.cursor/rules/*.mdc`, `.github/copilot-instructions.md`) lost
its registry match and degraded to `generic / session_start / global`. Two shipped surfaces
took that arm routinely — the MCP `validate` tool whenever no daemon is already warm, and
every run on a platform with no daemon at all — and the wrong map was then persisted into the
whole-map cache, so even a later warm run served it.

This drives BOTH arms end to end on the real bundled model over one fixture and requires the
per-file attribution to be identical. The daemon arm runs the real client request builder and
the real daemon-side handler, wired together over a loopback socket instead of a forked
daemon process: no fork, no socket file, no shared ~/.reporails state — but the same bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_onnx_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
)
requires_model = pytest.mark.skipif(not _onnx_path.exists(), reason="Bundled ONNX model not available")


class _LoopbackDaemonSock:
    """Serves the client's real request with the real daemon handler, in this process."""

    def __init__(self) -> None:
        self.pending = b""
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, payload: bytes) -> None:
        from reporails_cli.core.mapper import daemon

        request = json.loads(payload.decode("utf-8"))
        response = daemon._handle_map_ruleset(request, None)
        self.pending = (json.dumps(response) + "\n").encode("utf-8")

    def recv(self, size: int) -> bytes:
        chunk, self.pending = self.pending[:size], self.pending[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _build_fixture(root: Path) -> list[Path]:
    (root / ".cursor" / "rules").mkdir(parents=True)
    (root / ".github").mkdir()
    (root / ".cursor" / "rules" / "style.mdc").write_text(
        '---\ndescription: Python style rules\nglobs:\n  - "**/*.py"\nalwaysApply: false\n---\n\n'
        "You MUST keep functions under fifty lines.\nNever use a bare except clause here.\n",
        encoding="utf-8",
    )
    (root / ".github" / "copilot-instructions.md").write_text(
        "# Copilot instructions\n\nAlways annotate public functions.\nYou MUST prefer pathlib here.\n",
        encoding="utf-8",
    )
    (root / "CLAUDE.md").write_text(
        "# Project instructions\n\nYou MUST run the tests before committing.\nNever edit generated files.\n",
        encoding="utf-8",
    )
    return [
        root / ".cursor" / "rules" / "style.mdc",
        root / ".github" / "copilot-instructions.md",
        root / "CLAUDE.md",
    ]


def _attribution(ruleset_map: Any, root: Path) -> list[tuple[str, str, str, tuple[str, ...], str]]:
    return sorted(
        (
            Path(f.path).relative_to(root).as_posix(),
            f.loading,
            f.scope,
            tuple(f.globs),
            f.agent,
        )
        for f in ruleset_map.files
    )


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_in_process_and_daemon_arms_attribute_files_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same project, same file set: both arms must classify every file the same way.

    Each arm gets its own cache dir so the second arm cannot be served the first arm's
    stored map — the comparison is between two real maps, not one map read twice.
    """
    from reporails_cli.core.pipeline import mapping

    project = tmp_path / "proj"
    project.mkdir()
    files = _build_fixture(project)

    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: tmp_path / "cache-daemon"
    )
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: {"ok": True})
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.connect", _LoopbackDaemonSock)
    daemon_map = mapping.map_instruction_files(project, list(files), spawn_daemon=False)
    assert daemon_map is not None

    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: tmp_path / "cache-in-process"
    )
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: False)
    in_process_map = mapping.map_instruction_files(project, list(files), spawn_daemon=False)
    assert in_process_map is not None

    assert _attribution(in_process_map, project) == _attribution(daemon_map, project)
    # Pin the correct values too — equality alone would also hold if both arms were wrong.
    assert _attribution(in_process_map, project) == [
        (".cursor/rules/style.mdc", "on_demand", "path_scoped", ("**/*.py",), "cursor"),
        (".github/copilot-instructions.md", "session_start", "global", (), "copilot"),
        ("CLAUDE.md", "session_start", "global", (), "claude"),
    ]


@pytest.mark.integration
@pytest.mark.subsys_caching
def test_whole_map_cache_entry_is_not_shared_across_project_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A map built under one root must never be served to a run rooted elsewhere.

    The same `.cursor/rules/*.mdc` file is a cursor rule from the project root and an
    unmatched generic file from inside `.cursor/rules/`; one cache entry cannot be both.
    """
    from reporails_cli.core.cache.full_map_cache import FullMapCache, compute_identity
    from reporails_cli.core.platform.dto.ruleset import (
        EMBEDDING_MODEL,
        SCHEMA_VERSION,
        FileRecord,
        RulesetMap,
        RulesetSummary,
    )

    project = tmp_path / "proj"
    nested = project / ".cursor" / "rules"
    nested.mkdir(parents=True)
    rule = nested / "style.mdc"
    rule.write_text("You MUST keep functions short.\n", encoding="utf-8")

    cache = FullMapCache(tmp_path / "cache")
    stored = RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at="2026-09-20T00:00:00Z",
        files=(FileRecord(path=str(rule), content_hash="sha256:abc", loading="on_demand", agent="cursor"),),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )
    cache.put(compute_identity([rule], root=project), stored)

    assert cache.get(compute_identity([rule], root=project)) is not None
    assert cache.get(compute_identity([rule], root=nested)) is None

"""Tests for MCP server registration (core/mcp_install.py)."""

from __future__ import annotations

import json
from pathlib import Path

from reporails_cli.core.mcp_install import detect_mcp_targets, write_mcp_config

# ---------------------------------------------------------------------------
# detect_mcp_targets
# ---------------------------------------------------------------------------


def test_detect_claude_target(tmp_path: Path) -> None:
    """Claude agent → .mcp.json target."""
    (tmp_path / "CLAUDE.md").write_text("# Instructions\n")
    targets = detect_mcp_targets(tmp_path)
    assert len(targets) == 1
    agent_id, config_path = targets[0]
    assert agent_id == "claude"
    assert config_path == tmp_path / ".mcp.json"


def test_detect_copilot_target(tmp_path: Path) -> None:
    """Copilot agent → .vscode/mcp.json target."""
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "copilot-instructions.md").write_text("# Copilot\n")
    targets = detect_mcp_targets(tmp_path)
    assert len(targets) == 1
    agent_id, config_path = targets[0]
    assert agent_id == "copilot"
    assert config_path == tmp_path / ".vscode" / "mcp.json"


def test_detect_multiple_agents(tmp_path: Path) -> None:
    """Multiple agents detected → multiple targets."""
    (tmp_path / "CLAUDE.md").write_text("# Instructions\n")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "copilot-instructions.md").write_text("# Copilot\n")
    targets = detect_mcp_targets(tmp_path)
    agent_ids = {t[0] for t in targets}
    assert "claude" in agent_ids
    assert "copilot" in agent_ids


def test_skips_unsupported_agents(tmp_path: Path) -> None:
    """Aider and generic agents have no MCP config → skipped."""
    (tmp_path / "CONVENTIONS.md").write_text("# Conventions\n")
    (tmp_path / ".aider.conf.yml").write_text("model: gpt-4\n")
    targets = detect_mcp_targets(tmp_path)
    agent_ids = {t[0] for t in targets}
    assert "aider" not in agent_ids
    assert "generic" not in agent_ids


def test_no_agents_detected(tmp_path: Path) -> None:
    """Empty project → empty list."""
    targets = detect_mcp_targets(tmp_path)
    assert targets == []


# ---------------------------------------------------------------------------
# write_mcp_config
# ---------------------------------------------------------------------------


def test_creates_new_config(tmp_path: Path) -> None:
    """Creates fresh config when file does not exist."""
    config_path = tmp_path / ".mcp.json"
    result = write_mcp_config(config_path)

    assert result is True
    data = json.loads(config_path.read_text())
    assert "mcpServers" in data
    assert "reporails" in data["mcpServers"]
    assert data["mcpServers"]["reporails"]["command"] == "uvx"
    assert "reporails-mcp" in data["mcpServers"]["reporails"]["args"]


def test_creates_parent_dirs(tmp_path: Path) -> None:
    """Creates parent directories when needed."""
    config_path = tmp_path / ".vscode" / "mcp.json"
    result = write_mcp_config(config_path)

    assert result is True
    assert config_path.exists()
    data = json.loads(config_path.read_text())
    assert "reporails" in data["mcpServers"]


def test_merges_into_existing(tmp_path: Path) -> None:
    """Preserves existing mcpServers entries when merging."""
    config_path = tmp_path / ".mcp.json"
    existing = {
        "mcpServers": {
            "other-server": {"command": "node", "args": ["server.js"]},
        }
    }
    config_path.write_text(json.dumps(existing))

    write_mcp_config(config_path)

    data = json.loads(config_path.read_text())
    assert "other-server" in data["mcpServers"]
    assert "reporails" in data["mcpServers"]


def test_updates_existing_entry(tmp_path: Path) -> None:
    """Overwrites existing reporails entry (e.g., migrating from ails-mcp)."""
    config_path = tmp_path / ".mcp.json"
    existing = {
        "mcpServers": {
            "reporails": {
                "command": "uvx",
                "args": ["--refresh", "--from", "reporails-cli", "ails-mcp"],
            }
        }
    }
    config_path.write_text(json.dumps(existing))

    write_mcp_config(config_path)

    data = json.loads(config_path.read_text())
    assert "reporails-mcp" in data["mcpServers"]["reporails"]["args"]
    assert "ails-mcp" not in data["mcpServers"]["reporails"]["args"]


def test_handles_malformed_json(tmp_path: Path) -> None:
    """Recovers from malformed JSON by creating fresh config."""
    config_path = tmp_path / ".mcp.json"
    config_path.write_text("{not valid json")

    result = write_mcp_config(config_path)

    assert result is True
    data = json.loads(config_path.read_text())
    assert "reporails" in data["mcpServers"]

#!/usr/bin/env node

import { execSync, spawn } from "node:child_process";
import { platform } from "node:os";
import { argv, exit } from "node:process";

const PYPI_PACKAGE = "reporails-cli";
const MCP_COMMAND = "ails-mcp";
const CLI_COMMAND = "ails";

const HELP = `
reporails — Score your CLAUDE.md files

Usage:
  reporails install [--scope user|project]   Register MCP server with Claude Code
  reporails uninstall [--scope user|project] Remove MCP server from Claude Code
  reporails check [PATH] [OPTIONS]           Validate instruction files
  reporails <command> [args...]              Proxy any command to ails CLI

Examples:
  npx @reporails/cli install          # Add MCP server (user scope)
  npx @reporails/cli check .          # Score your setup
  npx @reporails/cli explain S1       # Explain a rule

Prerequisites:
  Node.js >= 18 (uv is auto-installed if missing)
`.trim();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function commandExists(cmd) {
  try {
    execSync(`${platform() === "win32" ? "where" : "which"} ${cmd}`, {
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function ensureUv() {
  if (commandExists("uv")) return;

  console.log("uv not found — installing...");
  try {
    if (platform() === "win32") {
      execSync(
        'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"',
        { stdio: "inherit" },
      );
    } else {
      execSync("curl -LsSf https://astral.sh/uv/install.sh | sh", {
        stdio: "inherit",
      });
    }
  } catch {
    console.error("Failed to install uv. Install manually: https://docs.astral.sh/uv/");
    exit(1);
  }

  if (!commandExists("uv")) {
    console.error(
      "uv was installed but is not on PATH. Restart your shell or add it to PATH, then retry.",
    );
    exit(1);
  }
}

function parseScope(args) {
  const idx = args.indexOf("--scope");
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return "user";
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

function install(args) {
  if (!commandExists("claude")) {
    console.error(
      "Claude Code CLI not found.\nInstall it from: https://docs.anthropic.com/en/docs/claude-code",
    );
    exit(1);
  }

  ensureUv();

  const scope = parseScope(args);
  const cmd = `claude mcp add --scope ${scope} reporails -- uvx --from ${PYPI_PACKAGE} ${MCP_COMMAND}`;
  console.log(`Registering MCP server (scope: ${scope})...`);

  try {
    execSync(cmd, { stdio: "inherit" });
    console.log("\nDone. Restart Claude Code to activate the MCP server.");
  } catch {
    console.error("Failed to register MCP server.");
    exit(1);
  }
}

function uninstall(args) {
  if (!commandExists("claude")) {
    console.error(
      "Claude Code CLI not found.\nInstall it from: https://docs.anthropic.com/en/docs/claude-code",
    );
    exit(1);
  }

  const scope = parseScope(args);
  const cmd = `claude mcp remove --scope ${scope} reporails`;
  console.log(`Removing MCP server (scope: ${scope})...`);

  try {
    execSync(cmd, { stdio: "inherit" });
    console.log("\nDone. MCP server removed.");
  } catch {
    console.error("Failed to remove MCP server.");
    exit(1);
  }
}

function proxy(args) {
  ensureUv();

  const child = spawn("uvx", ["--from", PYPI_PACKAGE, CLI_COMMAND, ...args], {
    stdio: "inherit",
  });

  child.on("error", (err) => {
    console.error(`Failed to run ails: ${err.message}`);
    exit(1);
  });

  child.on("close", (code) => {
    exit(code ?? 0);
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const args = argv.slice(2);
const subcommand = args[0];

if (!subcommand || subcommand === "--help" || subcommand === "-h") {
  console.log(HELP);
  exit(0);
}

switch (subcommand) {
  case "install":
    install(args.slice(1));
    break;
  case "uninstall":
    uninstall(args.slice(1));
    break;
  default:
    proxy(args);
    break;
}

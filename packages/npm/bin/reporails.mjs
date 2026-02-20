#!/usr/bin/env node

import { execSync, spawn } from "node:child_process";
import { platform } from "node:os";
import { argv, exit } from "node:process";

const PYPI_PACKAGE = "reporails-cli";
const CLI_COMMAND = "ails";

const HELP = `
reporails — Score your CLAUDE.md files

Usage:
  reporails install [PATH]                 Install MCP server for detected agents
  reporails check [PATH] [OPTIONS]           Validate instruction files
  reporails explain RULE_ID                  Show rule details
  reporails map [PATH] [--save]              Discover project structure
  reporails update                           Update rules framework + recommended
  reporails update --check                   Check for updates without installing
  reporails update --recommended             Update recommended rules only
  reporails update --cli                     Upgrade CLI package itself
  reporails dismiss RULE_ID                  Dismiss a semantic finding
  reporails version                          Show version info
  reporails <command> [args...]              Proxy any command to ails CLI

Examples:
  npx @reporails/cli install           # Install MCP server
  npx @reporails/cli check            # Score your setup
  npx @reporails/cli explain CORE:S:0001  # Explain a rule
  npx @reporails/cli update           # Update rules + recommended

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

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

function proxy(args) {
  ensureUv();

  const child = spawn("uvx", ["--refresh", "--from", PYPI_PACKAGE, CLI_COMMAND, ...args], {
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

// All subcommands proxy to the Python CLI
proxy(args);

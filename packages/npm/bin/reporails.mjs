#!/usr/bin/env node

import { execSync, spawn } from "node:child_process";
import { platform } from "node:os";
import { argv, exit } from "node:process";

const PYPI_PACKAGE = "reporails-cli";
const CLI_COMMAND = "ails";

const HELP = `
ails — Validate and score AI instruction files

Usage:
  ails check [TARGET...] [OPTIONS]       Validate and score your instruction files
  ails explain RULE_ID                   Show what a rule checks, by ID or slug
  ails rules [list|agents|capabilities]  Browse the framework rule registry
  ails login                             Sign this machine in through your browser
  ails logout                            Sign this machine out
  ails config [get|set|list]             Get and set project configuration
  ails install                           Put ails on PATH, print how to connect your agent
  ails update                            Update ails to the latest version
  ails version                           Show the version and install method

Examples:
  npx @reporails/cli check                # Validate your setup
  npx @reporails/cli install              # Put ails on PATH + next-step guidance
  npx @reporails/cli explain CORE:S:0001  # Explain a rule

Aliases:
  ails, reporails — both work after global install

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

  const child = spawn("uvx", ["--refresh-package", PYPI_PACKAGE, "--from", PYPI_PACKAGE, CLI_COMMAND, ...args], {
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

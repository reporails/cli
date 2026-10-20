#!/usr/bin/env node

import { execSync, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { delimiter, join } from "node:path";
import { argv, env, exit } from "node:process";

const PYPI_PACKAGE = "reporails-cli";
const CLI_COMMAND = "ails";
const VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;

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

// The folders Astral's uv installer writes to, in the installer's own order.
function uvInstallDirs() {
  const dirs = [];
  if (env.UV_INSTALL_DIR) dirs.push(env.UV_INSTALL_DIR);
  if (env.XDG_BIN_HOME) dirs.push(env.XDG_BIN_HOME);
  if (env.XDG_DATA_HOME) dirs.push(join(env.XDG_DATA_HOME, "..", "bin"));
  dirs.push(join(homedir(), ".local", "bin"));
  return dirs;
}

function findInstalledUvx() {
  const file = platform() === "win32" ? "uvx.exe" : "uvx";
  const dir = uvInstallDirs().find((d) => existsSync(join(d, file)));
  return dir ? { cmd: join(dir, file), dir } : null;
}

// Returns the uvx to run: on PATH, else in the installer's folders, else
// installed first. `dir` is set when uvx is not on PATH.
function ensureUvx() {
  if (commandExists("uvx")) return { cmd: "uvx", dir: null };
  const found = findInstalledUvx();
  if (found) return found;

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

  const installed = commandExists("uvx") ? { cmd: "uvx", dir: null } : findInstalledUvx();
  if (!installed) {
    console.error(
      `uv was installed but uvx was not found on PATH or in ${uvInstallDirs().join(", ")}. Add uv's folder to PATH, then retry.`,
    );
    exit(1);
  }
  return installed;
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

function proxy(args) {
  const uvx = ensureUvx();
  const childEnv = { ...env, AILS_LAUNCHER: "npm" };
  if (uvx.dir) childEnv.PATH = env.PATH ? `${uvx.dir}${delimiter}${env.PATH}` : uvx.dir;

  const child = spawn(uvx.cmd, ["--from", `${PYPI_PACKAGE}==${VERSION}`, CLI_COMMAND, ...args], {
    stdio: "inherit",
    env: childEnv,
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

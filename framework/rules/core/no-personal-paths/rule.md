---
id: CORE:G:0011
slug: no-personal-paths
title: No Personal Paths
category: governance
type: deterministic
severity: low
match: {format: [freeform, frontmatter, schema_validated]}
---

# No Personal Paths

Instruction files must not contain a literal personal home-directory path. A path such as `/home/alice/projects/x` leaks the author's username and machine layout into a committed file, and it breaks for every other user and every CI runner.

The check reports every line that holds such a path, in prose and in code blocks, in the file you wrote and in any file it imports with `@path` (the finding names the imported file and its line). It reports:

- a Linux home path: `/home/<name>/…`
- a macOS home path: `/Users/<name>/…`
- a Windows profile path: `C:\Users\<name>\…`, with either slash style and any drive letter

A reference to a home directory is not a personal path. The check leaves these alone: `~`, `$HOME`, `${HOME}`, `%USERPROFILE%`, `$USER`, a placeholder (`<user>`, `<name>`, `{user}`, `{{ user }}`), and the generic account names `user`, `username`, `you`, `me`, `runner`, `ubuntu`, `ec2-user`, `node`, `root`, `vscode` and `codespace`. It also leaves alone `/Users/Shared/`, `/home/linuxbrew/`, and the Windows system profiles `C:\Users\Public\`, `C:\Users\Default\`, `C:\Users\Default User\`, `C:\Users\All Users\` and `C:\Users\WDAGUtilityAccount\`, with either slash style and any drive letter.

## Antipatterns

- Writing `cd /home/alice/projects/x` in a setup section -- the check reports the line, because the path only exists on the author's machine.
- Pointing at `/Users/bob/dev/config.yml` in a code block -- the check scans fenced code blocks too.
- Quoting `C:\Users\carol\repo` as the checkout location -- the check reports Windows paths with either slash style.
- Importing a file with `@docs/setup.md` that holds a personal path -- the check reports it in the imported file.

## Pass / Fail

### Pass

~~~~markdown
## Setup

Clone the repo to `~/projects/x` or `$HOME/projects/x`.
On Windows use `%USERPROFILE%\repo`.
CI runs in `/home/runner/work/x` on GitHub Actions.
Replace `/home/<name>/` with your own home directory.
~~~~

### Fail

~~~~markdown
## Setup

cd /home/alice/projects/x
Config lives at /Users/bob/dev/config.yml
The checkout is C:\Users\carol\repo
~~~~

## Limitations

Detects a home path of the form `/home/<name>/`, `/Users/<name>/` or `C:\Users\<name>\`, and a name with no trailing slash when the path ends there. A personal account that is literally called one of the generic names (for example `node`) is not reported. Does not detect other user-specific locations such as `/root/` or a mounted path like `/mnt/c/Users/<name>/`, a username written outside a home path, or a path assembled from separate parts.

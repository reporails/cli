---
id: CORE:G:0012
slug: no-piped-remote-code
title: No Piped Remote Code
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: ci
severity: medium
match: {format: [freeform, frontmatter, schema_validated]}
---

# No Piped Remote Code

Instructions and hook commands must not download code and run it unseen. An agent that follows the file runs whatever the server returns that day, with the user's permissions.

The check reports every line that fetches code and executes it in the same step, in prose and in code blocks, in the file you wrote and in any file it imports with `@path` (the finding names the imported file and its line), and in a hook `command` of a settings file. It reports:

- `curl` or `wget` piped into a shell or interpreter: `curl -LsSf https://… | sh`, `wget -qO- https://… | sudo bash`, `… | python3`, `… | node`, `… | perl`, `… | ruby`, also behind `sudo`
- a download run through process or command substitution: `bash <(curl -s https://…)`, `source <(curl …)`, `sh -c "$(curl -fsSL https://…)"`, `eval "$(curl …)"`
- PowerShell that evaluates a download: `iwr https://… | iex`, `irm https://… | iex`, `Invoke-Expression (Invoke-WebRequest …)`, `iex (New-Object Net.WebClient).DownloadString(…)`

A download that is saved is not reported, and neither is output piped to a tool that only reads it: `curl -o install.sh https://…`, `curl -LO …`, `curl … | jq`, `curl … | grep`, `curl … | tee file`, `curl … | python -m json.tool`. Package installs (`pip install`, `npm install`) are not reported either.

The fix is to download the script to a file, review it, pin a checksum or a version, then run it.

## Antipatterns

- Telling the agent to install a tool with `curl -fsSL https://example.com/install.sh | bash` -- the script is not reviewed, and it can change between two runs.
- A hook `command` that pipes a download into `sh` -- the hook runs on every matching event, so it fetches and runs new code each time.
- Writing `iwr https://example.com/setup.ps1 | iex` for Windows setup -- the same unseen execution under PowerShell.

## Pass / Fail

### Pass

~~~~markdown
## Install

Download the installer, review it, check its checksum, then run it:

```bash
curl -o install.sh https://example.com/install.sh
sha256sum -c install.sh.sha256
sh install.sh
```
~~~~

### Fail

~~~~markdown
## Install

```bash
curl -LsSf https://example.com/install.sh | sh
wget -qO- https://example.com/setup.sh | sudo bash
bash <(curl -s https://example.com/setup.sh)
irm https://example.com/setup.ps1 | iex
```
~~~~

## Limitations

Uses pattern matching on a single line, so it reports a fetch and run joined on one line and misses one split across lines, behind a variable, or written inside a script it cannot see. A line that only mentions such a command in prose (for example, a warning that quotes `curl … | sh`) is reported too. Fetch tools other than `curl`, `wget` and PowerShell web cmdlets are not recognized.

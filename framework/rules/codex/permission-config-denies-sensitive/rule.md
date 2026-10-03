---
id: CODEX:G:0002
slug: permission-config-denies-sensitive
title: Permission Config Denies Sensitive
category: governance
type: mechanical
enforcement_required: true
enforcement_mechanism: permission
severity: medium
backed_by: []
match: {type: config}
supersedes: CORE:G:0005
source: https://learn.chatgpt.com/docs/config-file/config-advanced
---
# Permission Config Denies Sensitive

Codex has no deny list. It keeps secrets, credentials, and private keys out of reach through its sandbox, which stays on unless the configuration turns it off. A `config.toml` must therefore not set `sandbox_mode = "danger-full-access"`, the value that disables sandboxing entirely.

This is the Codex form of `CORE:G:0005`; Claude and Gemini settings files keep the `permissions.deny` list form.

## Antipatterns

- **Sandbox turned off.** Setting `sandbox_mode = "danger-full-access"` at the top level or in a profile, so the agent can read or write anything the user can.
- **Relying on `.gitignore` alone.** Excluding sensitive files from version control does not stop the agent from reading them at runtime; the sandbox does.

## Pass / Fail

### Pass

```toml
sandbox_mode = "workspace-write"
```

### Fail

```toml
sandbox_mode = "danger-full-access"
```

## Limitations

Reports a configuration that sets `sandbox_mode` to `danger-full-access`. A configuration that leaves the sandbox setting out passes, because the sandbox is on by default. Does not verify the sandbox on the machine that runs Codex or any setting passed on the command line.

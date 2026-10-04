"""User-facing notices for the ``ails check`` heal path.

Small output emitters split out of ``main.py``
so the command module stays focused on orchestration. Each renders in the
active output format — plain console for humans, a single JSON object on the
``json`` / ``github`` machine channels.
"""

from __future__ import annotations

import json
import sys

from reporails_cli.interfaces.cli.helpers import console


def _notify_heal_scope_skips(n_skipped: int, output_format: str) -> None:
    """Tell the user heal skipped N files whose real path escapes the named scope.

    Without this a capability/dir heal over symlinks-into-a-shared-tree reports `0 fixes`
    and reads as "nothing to fix" when it actually refused to touch out-of-scope files.
    """
    if n_skipped <= 0 or output_format in ("json", "github"):
        return
    console.print(
        f"[dim]{n_skipped} file(s) skipped — they resolve outside the heal scope "
        f"(e.g. an in-tree symlink to a shared tree); heal will not write through them.[/dim]"
    )


def _emit_heal_auth_required(output_format: str) -> None:
    """Emit the --heal auth-required notice in the active output format (anon gets diagnosis, not fix).

    Under json/github the diagnosis already occupies stdout (anon still gets the free
    diagnosis), so the auth notice goes to stderr — stdout stays a single valid JSON
    object the consumer can parse, instead of two concatenated objects.
    """
    if output_format in ("json", "github"):
        print(
            json.dumps(
                {
                    "error": "heal_requires_auth",
                    "message": "Applying fixes (--heal) requires an account. Run `ails auth login`.",
                }
            ),
            file=sys.stderr,
        )
        return
    console.print(
        "[yellow]Applying fixes needs an account.[/yellow] A free account is enough — this is not a paid feature.\n"
        "  Run [bold]ails auth login[/bold] to enable [bold]--heal[/bold]."
    )


def _emit_heal_scope_refusal(output_format: str) -> None:
    """Emit the --heal scope-safety refusal in the active output format."""
    if output_format in ("json", "github"):
        print(
            json.dumps(
                {
                    "error": "heal_requires_target",
                    "message": "--heal writes files and needs an explicit target, --dry-run, or --cwd.",
                }
            )
        )
        return
    console.print(
        "[red]✗ --heal writes to files and needs an explicit target.[/red]\n"
        "  Name what to fix (e.g. [bold]ails check CLAUDE.md --heal[/bold] or "
        "[bold]ails check skills --heal[/bold]),\n"
        "  preview the whole project with [bold]--dry-run[/bold], or opt into a "
        "whole-project rewrite with [bold]--cwd[/bold]."
    )

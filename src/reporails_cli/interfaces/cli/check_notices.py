"""User-facing notices for the ``ails check`` heal path.

Small output emitters split out of ``main.py``
so the command module stays focused on orchestration. Each renders in the
active output format — plain console for humans, a single JSON object on the
``json`` / ``github`` machine channels.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from reporails_cli.core.heal.apply import heal_withheld_for_run
from reporails_cli.interfaces.cli.check_orchestration import _dispatch_output
from reporails_cli.interfaces.cli.helpers import _print_no_instruction_files, console

if TYPE_CHECKING:
    from reporails_cli.interfaces.cli.check_flow import CheckState


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


def _emit_heal_withheld(output_format: str, *, funnel_error: object, tier: str | None, server_replied: bool) -> None:
    """Emit why --heal wrote nothing, in the active output format; the diagnosis is still complete.

    Under json/github the diagnosis owns stdout, so the notice goes to stderr — stdout stays a
    single valid JSON object the consumer can parse.
    """
    code, message = heal_withheld_for_run(
        error=getattr(funnel_error, "error", None),
        tier=tier,
        funnel_tier=getattr(funnel_error, "tier", None),
        server_replied=server_replied,
    )
    if output_format in ("json", "github"):
        print(json.dumps({"error": code, "message": message}), file=sys.stderr)
        return
    console.print(f"[yellow]{message}[/yellow]")


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


def _agent_is_pinned(state: CheckState) -> bool:
    """True when the run is set to one agent: ``--agent`` or the configured ``default_agent``."""
    if state.inputs.agent:
        return True
    from reporails_cli.core.platform.config.config import get_project_config

    return bool(get_project_config(state.targets.target).default_agent)


def _emit_empty_run(state: CheckState) -> None:
    """Render a run with nothing in scope — through the SAME surfaces a normal run uses.

    A run that discovers no instruction files is an ordinary result over an empty
    finding set, not a different contract. The machine surfaces therefore format an
    empty ``CombinedResult`` with the normal dispatcher, so `json` keeps its one
    top-level shape (``offline`` / ``tier`` / ``quality`` / ``level`` / ``files`` /
    ``stats`` / ``server_error``) and `github` emits an empty annotation set. Emitting
    a second, smaller envelope here instead forced every machine consumer — the
    GitHub Action's ``parse_result.py``, a CI ``min-score`` gate, an agent reading
    the JSON — to branch on two incompatible shapes, and made a scoped run that
    silently matched nothing indistinguishable from a clean one. Text keeps its
    human message, which says plainly that nothing was found.
    """
    if state.targets.output_format in ("json", "github"):
        from reporails_cli.core.platform.runtime.merger import CombinedResult

        _dispatch_output(
            state.targets.output_format,
            CombinedResult(),
            None,
            0.0,
            set(),
            state.targets.target,
            state.inputs.ascii_mode,
            state.inputs.verbose,
            None,
            None,
        )
        return
    whole_project = not state.targets.capability_specs and all(
        t == state.inputs.project_root for t in state.targets.path_targets
    )
    others = state.scope.detected if whole_project and _agent_is_pinned(state) else None
    _print_no_instruction_files(state.scope.effective_agent, console, others)

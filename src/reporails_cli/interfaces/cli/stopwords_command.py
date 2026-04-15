"""CLI command group: ails stopwords — vocab extraction and sync."""

from __future__ import annotations

from pathlib import Path

import typer

from reporails_cli.interfaces.cli.helpers import console

stopwords_app = typer.Typer(
    name="stopwords",
    help="Manage term-based regex patterns via vocab.yml.",
    no_args_is_help=True,
)


@stopwords_app.command("extract")
def stopwords_extract(
    rules_root: str = typer.Option(
        ".",
        "--rules-root",
        help="Rules directory root (default: current dir)",
    ),
) -> None:
    """Extract alternation terms from checks.yml into vocab.yml files."""
    from reporails_cli.core.stopwords import extract_all, write_vocab

    root = Path(rules_root).resolve()
    if not root.exists():
        console.print(f"[red]Error:[/red] Path not found: {root}")
        raise typer.Exit(2)

    results = extract_all(root)

    written = 0
    skipped = 0
    for er in results:
        if er.vocab:
            write_vocab(er.rule_dir, er.vocab)
            slug = er.rule_dir.name
            console.print(f"  [green]+[/green] {slug}: {er.message}")
            written += 1
        else:
            skipped += 1

    console.print()
    console.print(f"Extracted: {written} vocab.yml files written, {skipped} skipped")


@stopwords_app.command("sync")
def stopwords_sync(
    rules_root: str = typer.Option(
        ".",
        "--rules-root",
        help="Rules directory root (default: current dir)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would change without writing",
    ),
) -> None:
    """Compile vocab.yml terms into checks.yml patterns."""
    from reporails_cli.core.stopwords_sync import sync_all

    root = Path(rules_root).resolve()
    if not root.exists():
        console.print(f"[red]Error:[/red] Path not found: {root}")
        raise typer.Exit(2)

    results = sync_all(root, dry_run=dry_run)

    if not results:
        console.print("No vocab.yml files found.")
        return

    total_updated = 0
    total_skipped = 0
    for sr in results:
        slug = sr.rule_dir.name
        if sr.updated:
            prefix = "[dim]dry-run:[/dim] " if dry_run else ""
            console.print(f"  {prefix}[green]+[/green] {slug}: {sr.updated} pattern(s) updated")
            total_updated += sr.updated
        if sr.skipped:
            total_skipped += sr.skipped
        for msg in sr.messages:
            if "no check matching" in msg or "failed" in msg:
                console.print(f"  [yellow]![/yellow] {slug}: {msg}")

    console.print()
    label = "Would update" if dry_run else "Updated"
    console.print(f"{label}: {total_updated} pattern(s) across {len(results)} rule(s), {total_skipped} skipped")

"""Seeded meaning-drift suite for the rewrite check, on the real mapper.

Each row pairs an original instruction with a rewrite that keeps its words. The drifted rows
(`expect_ok=False`) shift the meaning in one of five classes found by blind review of real
rewrites: an actor swapped, a statement turned into an order, a modal shift, a dropped `only`,
a narrowed scope. The faithful controls (`expect_ok=True`) reword without changing the meaning,
so the suite cannot pass by failing everything.

A drifted row the check passes is a known gap: it stays in the table as a strict xfail that turns
red the day the check learns it. A drift class found later is added here as a row (xfail until its
fix lands) before the fix.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.integration.test_preservation_wording import _verdict

_CHECKS = (
    "lost_instructions",
    "polarity_flips",
    "added_instructions",
    "lost_named",
    "invented_named",
    "repeated_named",
    "detached_constraints",
    "prohibition_scope_changed",
    "added_conditions",
    "dropped_conditions",
    "narrowed_instructions",
    "dangling_fragments",
    "hedge_made_absolute",
    "padded_lines",
    "relabelled_negative_headings",
    "lost_context",
    "moved_list_items",
    "removed_structure",
)


def _row(drift_class: str, original: str, rewrite: str, expect_ok: bool, gap: str = ""):
    """A drifted row the check passes (or a control it fails) carries `gap` and is a strict xfail."""
    kind = "control" if expect_ok else "drift"
    marks = [pytest.mark.xfail(strict=True, reason=f"known gap: {drift_class} — {gap}")] if gap else []
    return pytest.param(
        drift_class, original, rewrite, expect_ok, marks=marks, id=f"{drift_class}-{kind}-{rewrite[:30]}"
    )


_ROWS = [
    # actor-swap
    _row(
        "actor-swap",
        "The reviewer approves each migration before merge.",
        "The author approves each migration before merge.",
        False,
        "a swapped subject noun leaves word overlap and polarity intact",
    ),
    _row(
        "actor-swap",
        "The agent runs `pytest` after every change.",
        "The user runs `pytest` after every change.",
        False,
        "a swapped subject noun leaves word overlap and polarity intact",
    ),
    _row(
        "actor-swap",
        "The CI job publishes the wheel to PyPI.",
        "The maintainer publishes the wheel to PyPI.",
        False,
        "a swapped subject noun leaves word overlap and polarity intact",
    ),
    _row(
        "actor-swap",
        "The planner writes the spec and the builder reviews it.",
        "The builder writes the spec and the planner reviews it.",
        False,
        "swapped roles reuse the same words",
    ),
    _row(
        "actor-swap",
        "The reviewer approves each migration before merge.",
        "Each migration is approved by the reviewer before merge.",
        True,
    ),
    _row(
        "actor-swap",
        "The agent runs `pytest` after every change.",
        "After every change, the agent runs `pytest`.",
        True,
    ),
    # statement-to-order
    _row(
        "statement-to-order", "The agent runs `pytest` after every change.", "Run `pytest` after every change.", False
    ),
    _row("statement-to-order", "The CI job lints the code on every push.", "Lint the code on every push.", False),
    _row("statement-to-order", "The reviewer checks the migration for locks.", "Check the migration for locks.", False),
    _row("statement-to-order", "Logs go to stdout.", "Send logs to stdout.", False),
    _row("statement-to-order", "Run `pytest` after every change.", "After every change, run `pytest`.", True),
    _row("statement-to-order", "Check the migration for locks.", "Make sure to check the migration for locks.", True),
    # modal-shift
    _row("modal-shift", "Let the linter run before each commit.", "The linter runs before each commit.", False),
    _row(
        "modal-shift",
        "The agent may skip the tests for docs changes.",
        "The agent skips the tests for docs changes.",
        False,
        "a dropped `may` leaves a plain statement; no modal check",
    ),
    _row(
        "modal-shift",
        "You can use `make clean` to reset the build.",
        "You must use `make clean` to reset the build.",
        False,
        "`can` to `must` is no hedge or polarity change",
    ),
    _row("modal-shift", "You must run `pytest` before commits.", "You may run `pytest` before commits.", False),
    _row("modal-shift", "You must run `pytest` before commits.", "Run `pytest` before commits.", True),
    _row(
        "modal-shift",
        "You can use `make clean` to reset the build.",
        "Use `make clean` to reset the build if you need to.",
        True,
    ),
    # dropped-only
    _row("dropped-only", "Edit files only under `src/`.", "Edit files under `src/`.", False),
    _row(
        "dropped-only",
        "Use `make deploy` only for the staging cluster.",
        "Use `make deploy` for the staging cluster.",
        False,
    ),
    _row(
        "dropped-only",
        "Only the lead merges to main.",
        "The lead merges to main.",
        False,
        "a leading `Only` is no condition word the check reads",
    ),
    _row(
        "dropped-only",
        "Run migrations only after the backup finishes.",
        "Run migrations after the backup finishes.",
        False,
    ),
    _row(
        "dropped-only",
        "Edit files only under `src/`.",
        "Do not edit files outside `src/`.",
        True,
        "false positive: `only` read as a dropped condition and the `Do not` form as narrowing",
    ),
    _row(
        "dropped-only",
        "Use `make deploy` only for the staging cluster.",
        "For the staging cluster only, use `make deploy`.",
        True,
        "false positive: a fronted `only` phrase read as a dropped condition",
    ),
    # narrowed-scope
    _row(
        "narrowed-scope",
        "Run `pytest` before every commit.",
        "Run `pytest` before every commit on feature branches.",
        False,
    ),
    _row("narrowed-scope", "Review all migrations.", "Review the migrations in `db/`.", False),
    _row("narrowed-scope", "Never commit secrets.", "Never commit secrets to the public repo.", False),
    _row(
        "narrowed-scope",
        "Format every file with `ruff format`.",
        "Format every Python file with `ruff format`.",
        False,
        "a modifier before the noun after `every` is no restrictor",
    ),
    _row("narrowed-scope", "Review all migrations.", "Review every migration.", True),
    _row("narrowed-scope", "Format every file with `ruff format`.", "Use `ruff format` to format every file.", True),
]


def _fired(verdict: dict[str, Any]) -> list[str]:
    def _hit(value: Any) -> bool:
        return any(value.values()) if isinstance(value, dict) else bool(value)

    return [c for c in _CHECKS if _hit(verdict.get(c))]


@pytest.mark.subsys_server
@pytest.mark.integration
@pytest.mark.requires_model
@pytest.mark.parametrize(("drift_class", "original", "rewrite", "expect_ok"), _ROWS)
def test_meaning_drift_rows_on_the_real_mapper(tmp_path, drift_class, original, rewrite, expect_ok) -> None:
    verdict = _verdict(tmp_path, original, rewrite)
    assert verdict["ok"] is expect_ok, (
        f"{drift_class}: expected ok={expect_ok}, got ok={verdict['ok']}; "
        f"checks fired: {_fired(verdict) or 'none'}\n  original: {original}\n  rewrite:  {rewrite}"
    )

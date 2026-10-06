"""Mutation-killing behavioral tests for `runtime/merger.py`.

Targets the `CombinedResult.offline` default (L101). The three frozen-dataclass
mutants (L62 FindingItem, L77 CombinedStats, L92 CombinedResult) are equivalent:
none of these DTOs is ever hashed or set-inserted, so `frozen=True -> False`
is unobservable.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.runtime.merger import CombinedResult


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_combined_result_defaults_offline_true() -> None:
    # Kills L101 `offline: bool = True -> False`: a freshly built result is offline by default.
    assert CombinedResult().offline is True

"""Rewrite check: whether a rewritten instruction file kept everything the original had.

`take_snapshot` records the original; `compare` judges the rewrite against it.
"""

from reporails_cli.core.heal.preservation.compare import PRESERVATION_CONTRACT, check_rewrite, compare, failed_checks
from reporails_cli.core.heal.preservation.snapshot import Snapshot, is_instruction_heading, take_snapshot

__all__ = [
    "PRESERVATION_CONTRACT",
    "Snapshot",
    "check_rewrite",
    "compare",
    "failed_checks",
    "is_instruction_heading",
    "take_snapshot",
]

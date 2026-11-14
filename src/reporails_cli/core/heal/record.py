"""The heal record: what each heal-kept file looked like in the whole-project run after the heal, and
the comparison that names a healed file that has slipped since."""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import get_heal_record_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_int, as_object, as_str, opt_float
from reporails_cli.core.platform.dto.heal import HealedFile, HealRegression
from reporails_cli.core.platform.dto.platform import CombinedResult
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.core.platform.utils.utils import SCORE_DECIMALS

logger = logging.getLogger(__name__)


def _healed_file(entry: JsonObject) -> HealedFile:
    """One record entry; a score that is not a number reads as unscored."""
    rules = {rule: as_int(n, 0) for rule, n in as_object(entry.get("rules")).items()}
    return HealedFile(opt_float(entry.get("score")), rules, as_str(entry.get("healed_at")))


def read_record(root: Path) -> dict[str, HealedFile]:
    """The project's heal record by project-relative path; empty when there is none.

    A record that cannot be read or is not a record gives one warning and counts as no record.
    """
    path = get_heal_record_path(root)
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        files = document.get("files") if isinstance(document, dict) else None
        if not isinstance(files, dict):
            raise ValueError("it holds no `files` object")
        return {name: _healed_file(as_object(entry)) for name, entry in files.items()}
    except (OSError, ValueError) as exc:
        logger.warning("Ignoring the heal record %s: %s", path, exc)
        return {}


def record_healed(root: Path, kept: Mapping[str, tuple[float | None, dict[str, int]]]) -> None:
    """Upsert one entry per kept file (project-relative path -> score, per-rule finding counts), keeping
    the entries of every other file. Writes nothing when `kept` is empty."""
    if not kept:
        return
    when = datetime.now(UTC).isoformat()
    files: dict[str, JsonObject] = {
        name: {"score": entry.score, "rules": dict(entry.rules), "healed_at": entry.healed_at}
        for name, entry in read_record(root).items()
    }
    for name, (score, rules) in kept.items():
        files[name] = {"score": score, "rules": dict(rules), "healed_at": when}
    path = get_heal_record_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": files}, indent=2, sort_keys=True), encoding="utf-8")


def regressions(
    record: Mapping[str, HealedFile],
    scores: Mapping[str, float | None],
    counts: Mapping[str, Mapping[str, int]],
) -> tuple[HealRegression, ...]:
    """The recorded files the run shows slipping: score fell by at least a display step, or findings came back.

    `scores` is the run's score per scored file (`None` when unscored), `counts` its findings per rule per
    file. Scores are compared only when both are present. A file the run does not mention is skipped.
    """
    found: list[HealRegression] = []
    for name, healed in record.items():
        if name not in scores and name not in counts:
            continue
        now = scores.get(name)
        fell = (
            healed.score is not None
            and now is not None
            and round(now, SCORE_DECIMALS) < round(healed.score, SCORE_DECIMALS)
        )
        back = {
            rule: n - healed.rules.get(rule, 0)
            for rule, n in counts.get(name, {}).items()
            if n > healed.rules.get(rule, 0)
        }
        if fell or back:
            found.append(HealRegression(name, healed.score if fell else None, now if fell else None, back))
    return tuple(found)


def count_rules(rules: Iterable[str]) -> dict[str, int]:
    """How many times each rule id appears in `rules`."""
    return dict(Counter(rules))


def file_scores(result: CombinedResult, root: Path) -> dict[str, float]:
    """The 0-10 score of each scored file of `result` by its path relative to `root`; empty offline."""
    return {
        normalize_finding_path(fa.file, root): float(fa.display_score)
        for fa in result.per_file_analysis
        if fa.display_score is not None
    }


def heal_regressions(result: CombinedResult, root: Path) -> tuple[HealRegression, ...]:
    """The healed files `result` (an `ails check` run of the project at `root`) shows slipping since the
    heal; none when the project has no heal record."""
    record = read_record(root)
    if not record:
        return ()
    rules_of: dict[str, list[str]] = {}
    for finding in result.findings:
        rules_of.setdefault(normalize_finding_path(finding.file, root), []).append(finding.rule)
    counts = {name: count_rules(rules) for name, rules in rules_of.items()}
    return regressions(record, file_scores(result, root), counts)

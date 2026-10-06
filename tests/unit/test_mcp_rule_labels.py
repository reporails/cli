"""Red-first tests for the MCP `validate` reply's top-level `rules` map.

A bare rule code (`CORE:E:0004`) means nothing to the coding agent reading the reply
through an MCP client — it needs the rule's title and a docs link. `with_rule_labels`
(wired into every `bound_validate_payload` return path) adds ONE `{<rule id>: {"title",
"url"}}` entry per rule id named anywhere in the reply — per-file findings, `top_rules`,
workflow findings/relations, and `workflow.listed` — never once per finding.
"""

from __future__ import annotations

import json

import pytest

from reporails_cli.formatters.mcp import bound_validate_payload, rules_block, with_rule_labels

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]

# Real bundled rule ids (framework/rules/core) so title/url actually resolve.
_KNOWN_1 = "CORE:E:0004"  # instruction-elaboration
_KNOWN_2 = "CORE:E:0003"  # formatting-regime
_UNKNOWN = "CORE:ZZ:9999"  # not a real rule — must be omitted, never crash


def _payload_with_findings() -> dict:
    return {
        "level": "L2",
        "tier": "pro",
        "stats": {"total": 3},
        "files": {
            "a.md": {
                "findings": [
                    {"line": 1, "rule": _KNOWN_1, "message": "m1"},
                    {"line": 2, "rule": _KNOWN_2, "message": "m2"},
                ],
                "count": 2,
            },
            "b.md": {
                "findings": [{"line": 1, "rule": _KNOWN_1, "message": "m3"}],
                "count": 1,
            },
        },
        "workflow": {
            "summary": "s",
            "escape": "e",
            "locations": [
                {
                    "order": 1,
                    "element": "AGENTS.md",
                    "kind": "main",
                    "loading": "always",
                    "files": ["AGENTS.md"],
                    "importance": "gate_mover",
                    "findings": [
                        {"rule": _KNOWN_1, "file": "AGENTS.md", "line": 1, "pi": 0, "message": "m", "remedy": "r"}
                    ],
                    "relations": [],
                }
            ],
            "listed": [{"rule": _KNOWN_2, "reason": "long", "count": 5}],
        },
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_rules_block_carries_title_and_url_once_per_rule() -> None:
    """Every rule id named anywhere in the payload gets ONE `rules` entry — title + the
    `https://reporails.com/rules/core/<slug>` docs url — not one per finding."""
    rules = rules_block(_payload_with_findings())

    assert rules[_KNOWN_1]["title"] == "Instruction Elaboration"
    assert rules[_KNOWN_1]["url"] == "https://reporails.com/rules/core/instruction-elaboration"
    assert rules[_KNOWN_2]["title"] == "Formatting Effectiveness"
    assert rules[_KNOWN_2]["url"] == "https://reporails.com/rules/core/formatting-regime"
    # _KNOWN_1 fires 3 times (2 findings + 1 workflow finding) — still exactly one entry.
    assert len(rules) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_rules_block_omits_an_unresolvable_rule_id() -> None:
    """An unknown rule id (neither title nor url resolves) is omitted, not stubbed."""
    payload = _payload_with_findings()
    payload["files"]["a.md"]["findings"].append({"line": 9, "rule": _UNKNOWN, "message": "m9"})

    rules = rules_block(payload)

    assert _UNKNOWN not in rules
    assert set(rules) == {_KNOWN_1, _KNOWN_2}


@pytest.mark.unit
@pytest.mark.subsys_server
def test_rules_block_maps_raw_client_check_tokens_to_the_canonical_id() -> None:
    """A raw client-check token (`format`) keys the map under its canonical id (`CORE:E:0003`)
    — the same id the rest of the reply shows via `display_rule_id`."""
    payload = {"files": {"a.md": {"findings": [{"line": 1, "rule": "format", "message": "m"}], "count": 1}}}

    rules = rules_block(payload)

    assert set(rules) == {"CORE:E:0003"}
    assert "format" not in rules


@pytest.mark.unit
@pytest.mark.subsys_server
def test_rules_block_key_set_is_sorted() -> None:
    payload = _payload_with_findings()
    rules = rules_block(payload)
    assert list(rules) == sorted(rules)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_with_rule_labels_adds_one_top_level_rules_object() -> None:
    payload = _payload_with_findings()
    out = with_rule_labels(payload)
    assert set(out["rules"]) == {_KNOWN_1, _KNOWN_2}
    # everything else passes through untouched
    assert out["files"] == payload["files"]
    assert out["workflow"] == payload["workflow"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_with_rule_labels_is_a_no_op_on_a_payload_with_no_rule_ids() -> None:
    err = {"error": "path_not_found"}
    assert with_rule_labels(err) == err
    assert "rules" not in with_rule_labels(err)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bound_validate_payload_carries_rules_on_the_bounded_path() -> None:
    """The bounded (truncated) envelope still carries `rules` for the findings it kept.

    No workflow here, so file findings (not withheld) carry both rule ids through.
    """
    payload = _payload_with_findings()
    del payload["workflow"]
    bounded = bound_validate_payload(payload, per_file_limit=1, max_files=1)
    assert "rules" in bounded
    assert bounded["rules"][_KNOWN_1]["title"] == "Instruction Elaboration"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bound_validate_payload_carries_rules_on_the_pass_through_path() -> None:
    """A small payload that needs no truncation still gets the `rules` map added."""
    payload = _payload_with_findings()
    del payload["workflow"]
    out = bound_validate_payload(payload)
    assert set(out["rules"]) == {_KNOWN_1, _KNOWN_2}


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bound_validate_payload_drops_a_rule_id_the_workflow_strips_from_the_reply() -> None:
    """With a `workflow` present, per-file findings AND per-location findings are both
    withheld (workflow-first) — a rule id that only ever appeared in those spots (never in
    `workflow.listed`) no longer appears anywhere in the reply, so `rules` correctly omits
    it too. Only `_KNOWN_2` (named in `workflow.listed`) survives."""
    payload = _payload_with_findings()
    bounded = bound_validate_payload(payload)
    assert bounded["workflow"]["locations"][0]["finding_count"] == 1  # the count survives...
    assert set(bounded["rules"]) == {_KNOWN_2}, "...but the stripped finding's rule id does not"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bound_validate_payload_carries_rules_from_workflow_listed_when_findings_are_withheld() -> None:
    """Workflow-first mode withholds per-file findings entirely, but `workflow.listed` still
    names its rule — that rule must still resolve into `rules`."""
    payload = _payload_with_findings()
    # Force many files so per-file findings are withheld (workflow-first), leaving `listed`
    # (CORE:E:0003) as the only surviving rule mention alongside the one indexed location's
    # true finding_count (no findings/relations survive the index).
    bounded = bound_validate_payload(payload, max_files=1)
    assert bounded["files"] == {} or all(e["findings"] == [] for e in bounded["files"].values())
    assert _KNOWN_2 in bounded["rules"], "workflow.listed's rule must still resolve"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bounded_envelope_size_with_rule_labels_stays_bounded() -> None:
    """The `rules` map is one-entry-per-rule (not per-finding), so on a representative
    60-file / 40-finding-per-file payload capped to the default envelope (5 findings/file,
    25 files, one rule id repeated throughout) the added `rules` overhead is a small,
    near-constant slice of the bounded reply — never grows with the finding count."""
    payload = {
        "level": "L2",
        "tier": "pro",
        "stats": {"total": 60 * 40},
        "files": {
            f"file_{i}.md": {
                "findings": [{"line": j, "rule": _KNOWN_1, "message": "x" * 200} for j in range(40)],
                "count": 40,
            }
            for i in range(60)
        },
    }
    bounded = bound_validate_payload(payload, per_file_limit=5, max_files=25)
    bounded_without_rules = {k: v for k, v in bounded.items() if k != "rules"}
    bounded_size = len(json.dumps(bounded))
    size_without_rules = len(json.dumps(bounded_without_rules))
    added = bounded_size - size_without_rules

    # The rules map itself is tiny — one entry, not the 125 kept findings.
    assert len(bounded["rules"]) == 1
    assert added < 300, (
        f"`rules` added {added} bytes to a bounded reply of {bounded_size} — expected a single-entry cost"
    )
    assert added / bounded_size < 0.02, "rule labels must stay a small fraction of the bounded reply"

"""Red-first tests for the MCP `validate` output-size envelope.

The full per-file finding set on a large repo blew the single-line JSON `validate` result
past the harness per-tool-result token cap. `bound_validate_payload` caps the enumerated
findings (top-N per file, top files) while keeping every aggregate field whole, with a
`truncated` marker and a `full=true` opt-in. With a paid `workflow` present, the reply
carries the location index only (no findings/relations — those come from
`remedy_brief(path, location)`).
"""

from __future__ import annotations

import json

import pytest

from reporails_cli.formatters.listed_reasons import listed_reason_text
from reporails_cli.formatters.mcp import bound_validate_payload, with_rule_labels

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


def _big_payload(n_files: int, per_file: int) -> dict:
    return {
        "level": "L2",
        "tier": "free",
        "stats": {"total": n_files * per_file},
        "surface_health": [{"name": "agents", "score": 4, "finding_count": n_files * per_file}],
        "files": {
            f"file_{i}.md": {
                "findings": [{"line": j, "rule": "CORE:S:0001", "message": "x" * 200} for j in range(per_file)],
                "count": per_file,
            }
            for i in range(n_files)
        },
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_caps_findings_and_files_and_shrinks_payload():
    """Bounded default caps per-file findings + file count and is far smaller than the full set."""
    payload = _big_payload(n_files=60, per_file=40)
    full_size = len(json.dumps(payload))

    bounded = bound_validate_payload(payload, per_file_limit=5, max_files=25)

    assert len(bounded["files"]) == 25, "file count must be capped"
    assert all(len(e["findings"]) <= 5 for e in bounded["files"].values()), "per-file findings must be capped"
    assert len(json.dumps(bounded)) < full_size // 4, "bounded payload must be dramatically smaller"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_preserves_aggregate_and_true_counts_and_marks_truncated():
    """Aggregate fields stay whole; per-file `count` stays true; a `truncated` block is added."""
    payload = _big_payload(n_files=60, per_file=40)

    bounded = bound_validate_payload(payload, per_file_limit=5, max_files=25)

    assert bounded["stats"] == payload["stats"]
    assert bounded["surface_health"] == payload["surface_health"]
    assert bounded["level"] == "L2"
    assert all(e["count"] == 40 for e in bounded["files"].values()), "true finding count must survive truncation"
    assert bounded["truncated"]["findings_total"] == 60 * 40
    assert bounded["truncated"]["files_total"] == 60
    assert "full=true" in bounded["truncated"]["hint"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_passes_through_small_and_error_payloads():
    """A small payload is returned unchanged; an error payload (no `files`) passes through."""
    small = _big_payload(n_files=2, per_file=2)
    assert bound_validate_payload(small) == small
    assert "truncated" not in bound_validate_payload(small)

    err = {"error": "path_not_found"}
    assert bound_validate_payload(err) == err


def _workflow_payload(n_locations: int) -> dict:
    payload = _big_payload(n_files=2, per_file=2)
    payload["tier"] = "pro"
    payload["workflow"] = {
        "summary": "s",
        "escape": "e",
        "locations": [
            {
                "order": i,
                "element": f"the `skill-{i}` skill",
                "kind": "skills",
                "loading": "on_invocation",
                "files": [f"skills/s{i}/SKILL.md"],
                "importance": "gate_mover",
                "findings": [
                    {
                        "rule": "CORE:C:0042",
                        "file": f"skills/s{i}/SKILL.md",
                        "line": 1,
                        "pi": 0,
                        "message": "m",
                        "remedy": "r",
                    }
                ],
                "relations": [],
            }
            for i in range(1, n_locations + 1)
        ],
    }
    return payload


_INDEX_KEYS = {"order", "element", "kind", "loading", "files", "importance", "finding_count"}


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_envelope_carries_the_workflow_as_a_location_index_without_findings():
    """Each location keeps what orders and names it and its true `finding_count`; its findings
    and relations come with `remedy_brief(path, location)`, so the reply does not grow with the
    head's finding count."""
    payload = _workflow_payload(n_locations=30)

    index = bound_validate_payload(payload)["workflow"]

    assert all(set(loc) == _INDEX_KEYS for loc in index["locations"])
    assert index["locations"][0]["finding_count"] == 1
    assert index["summary"] == "s" and index["escape"] == "e"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_index_stays_small_whatever_the_head_s_findings():
    payload = _workflow_payload(n_locations=3)
    loc = payload["workflow"]["locations"][0]
    payload["workflow"]["locations"] = [
        {
            **loc,
            "order": i,
            "findings": [
                {
                    "rule": "CORE:C:0042",
                    "file": f"f{i}.md",
                    "line": n,
                    "pi": n,
                    "message": "x" * 150,
                    "remedy": "y" * 150,
                }
                for n in range(70)
            ],
        }
        for i in range(1, 13)
    ]
    assert len(json.dumps(bound_validate_payload(payload)["workflow"])) < 4_000


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_envelope_is_workflow_first_and_withholds_the_finding_enumeration():
    """With a `workflow` present the per-file finding lists are withheld (the surviving rows
    keep their counts) so the remedy is the location index, not the `ails check -v`
    enumeration beside it; the file-row cap still applies so the reply never grows with file
    count."""
    payload = _workflow_payload(n_locations=3)
    payload["files"] = _big_payload(n_files=30, per_file=20)["files"]

    bounded = bound_validate_payload(payload)

    assert len(bounded["files"]) == 25, "the file-row cap applies in workflow mode too"
    assert bounded["truncated"]["files_total"] == 30
    assert all(e["findings"] == [] and e["count"] == 20 for e in bounded["files"].values())
    assert [loc["order"] for loc in bounded["workflow"]["locations"]] == [1, 2, 3], "every location is indexed"
    assert bounded["truncated"]["findings_shown"] == 0
    assert bounded["truncated"]["findings_total"] == 600
    hint = bounded["truncated"]["hint"]
    assert "remedy_brief" in hint and "workflow.locations" in hint and "full=true" in hint
    assert len(json.dumps(bounded)) < len(json.dumps(payload)) // 5


@pytest.mark.unit
@pytest.mark.subsys_server
def test_anonymous_envelope_without_workflow_keeps_the_bounded_findings():
    """No workflow (anonymous) → the diagnosis + one-remedy-per-type findings stay the surface."""
    payload = _big_payload(n_files=60, per_file=40)
    bounded = bound_validate_payload(payload, per_file_limit=5, max_files=25)
    assert all(len(e["findings"]) == 5 for e in bounded["files"].values())


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_envelope_keeps_the_file_row_cap() -> None:
    # Workflow-first must not drop the file-row bound: a 400-file surface (a memory
    # directory) would otherwise grow the paid reply linearly with file count.
    payload = _workflow_payload(n_locations=2)
    payload["files"] = {f"memory/topic-{i:04d}.md": {"findings": [], "count": 3} for i in range(400)}
    bounded = bound_validate_payload(payload)
    assert len(bounded["files"]) == 25
    assert bounded["truncated"]["files_shown"] == 25
    assert bounded["truncated"]["files_total"] == 400
    assert all(entry["findings"] == [] and entry["count"] == 3 for entry in bounded["files"].values())


def _cross_file_rows(n: int) -> list[dict]:
    return [
        {
            "file_1": f"skills/a{i % 7}/SKILL.md",
            "file_2": "tests/CLAUDE.md",
            "line_1": i,
            "line_2": 3,
            "type": "overlap",
        }
        for i in range(n)
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_envelope_withholds_the_cross_file_rows_behind_full():
    # The line-pair rows are enumeration too: with a workflow present the locations that edit
    # locate the lines to act on, and the rows outgrow the rest of the reply.
    payload = _workflow_payload(n_locations=3)
    payload["cross_file"] = _cross_file_rows(1200)
    payload["stats"] = {"cross_file_overlaps": 7, "cross_file_repetitions": 0}

    bounded = bound_validate_payload(payload)

    assert "cross_file" not in bounded
    assert bounded["stats"] == payload["stats"], "the pair counts stay whole"
    assert (bounded["truncated"]["cross_file_shown"], bounded["truncated"]["cross_file_total"]) == (0, 1200)
    assert len(json.dumps(bounded)) < len(json.dumps(payload)) // 20


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_without_workflow_keeps_a_top_slice_of_cross_file_rows():
    payload = _big_payload(n_files=2, per_file=2)
    payload["cross_file"] = _cross_file_rows(300)

    bounded = bound_validate_payload(payload, cross_file_limit=25)

    assert bounded["cross_file"] == payload["cross_file"][:25]
    assert (bounded["truncated"]["cross_file_shown"], bounded["truncated"]["cross_file_total"]) == (25, 300)
    assert "full=true" in bounded["truncated"]["hint"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_cross_file_rows_are_bounded_when_no_file_lists_a_finding():
    # Every finding silenced or filtered, while the server still returns the line-pair rows.
    payload = {"files": {}, "stats": {"total_findings": 0}, "cross_file": _cross_file_rows(300)}

    bounded = bound_validate_payload(payload, cross_file_limit=25)

    assert len(bounded["cross_file"]) == 25
    assert bounded["truncated"]["cross_file_total"] == 300


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_keeps_cross_file_rows_under_the_cap_untouched():
    payload = _big_payload(n_files=2, per_file=2)
    payload["cross_file"] = _cross_file_rows(4)
    assert bound_validate_payload(payload) == payload


def _cross_file_coordinate_rows(n: int) -> list[dict]:
    return [
        {"file_1": f"skills/a{i % 7}/SKILL.md", "file_2": "tests/CLAUDE.md", "type": "overlap", "count": i}
        for i in range(n)
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_caps_cross_file_coordinates_like_cross_file():
    """`cross_file_coordinates` (the unpaid-tier sibling of `cross_file` — file-pair + count,
    no line numbers) is enumeration too, and was left completely uncapped (a free reply
    used to carry 46 uncapped rows). It gets the same top-slice
    treatment, with the true total surviving in `stats` and the cut noted in `truncated`."""
    payload = _big_payload(n_files=2, per_file=2)
    payload["cross_file_coordinates"] = _cross_file_coordinate_rows(300)

    bounded = bound_validate_payload(payload, cross_file_coord_limit=25)

    assert bounded["cross_file_coordinates"] == payload["cross_file_coordinates"][:25]
    assert bounded["truncated"]["cross_file_coordinates_shown"] == 25
    assert bounded["truncated"]["cross_file_coordinates_total"] == 300
    assert "full=true" in bounded["truncated"]["hint"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_cross_file_coordinates_are_bounded_when_no_file_lists_a_finding():
    payload = {"files": {}, "stats": {"total_findings": 0}, "cross_file_coordinates": _cross_file_coordinate_rows(46)}

    bounded = bound_validate_payload(payload, cross_file_coord_limit=10)

    assert len(bounded["cross_file_coordinates"]) == 10
    assert bounded["truncated"]["cross_file_coordinates_total"] == 46


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_keeps_cross_file_coordinates_under_the_cap_untouched():
    payload = _big_payload(n_files=2, per_file=2)
    payload["cross_file_coordinates"] = _cross_file_coordinate_rows(4)
    assert bound_validate_payload(payload) == payload


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_envelope_withholds_cross_file_coordinates_behind_full():
    """`cross_file_coordinates` never rides beside a paid `workflow` in practice (the two are
    tier-exclusive), but when both are present the workflow-first zeroing must cover it the
    same way `cross_file` already is, not leave it as the one uncapped list."""
    payload = _workflow_payload(n_locations=3)
    payload["cross_file_coordinates"] = _cross_file_coordinate_rows(300)

    bounded = bound_validate_payload(payload)

    assert "cross_file_coordinates" not in bounded
    assert (
        bounded["truncated"]["cross_file_coordinates_shown"],
        bounded["truncated"]["cross_file_coordinates_total"],
    ) == (
        0,
        300,
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_unpaid_default_envelope_stays_under_the_16k_size_bar_on_a_large_project():
    """The release size bar (`mcp.md` §7) applies without a tier qualifier, but an unpaid
    reply never carries a `workflow` — no server remediation to index — so it never took the
    workflow-first path that shrinks a paid reply. On the activepieces-scale sample this read
    28.6k-32.3k chars against the 16k bar. This reproduces
    that shape (many files with several findings each, plus many cross-file-coordinate rows,
    no workflow) with the library's *default* limits, and checks the whole bounded reply
    (minus the `rules` map, which the live size bar excludes) stays at or under 16k — while
    every file keeps its true `count` and the cut is named in `truncated`, so the totals
    a paying and a free caller both need are never dropped, only the listing is bounded."""
    payload = _big_payload(n_files=48, per_file=18)
    payload["cross_file_coordinates"] = _cross_file_coordinate_rows(46)
    payload["tier"] = "free"

    bounded = bound_validate_payload(payload)
    size_without_rules = len(json.dumps({k: v for k, v in bounded.items() if k != "rules"}))

    assert size_without_rules <= 16_000, f"bounded free-tier reply is {size_without_rules} chars"
    assert bounded["truncated"]["cross_file_coordinates_total"] == 46
    assert bounded["truncated"]["cross_file_coordinates_shown"] < 46
    assert all(entry["count"] == 18 for entry in bounded["files"].values()), "true per-file count survives"
    assert bounded["truncated"]["files_total"] == 48


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_groups_listed_rules_sharing_one_reason_code():
    """Two rules that share a reason code collapse into one group carrying the cli's own
    sentence once; a rule with another code gets its own group. Each rule keeps its `count`."""
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["listed"] = [
        {"rule": "CORE:E:0004", "reason": "no-gain", "count": 40},
        {"rule": "CORE:C:0005", "reason": "no-gain", "count": 1},
        {"rule": "CORE:S:0002", "reason": "unbacked", "count": 2},
    ]

    listed = bound_validate_payload(payload)["workflow"]["listed"]

    assert listed == [
        {
            "reason": listed_reason_text("no-gain"),
            "rules": [{"rule": "CORE:E:0004", "count": 40}, {"rule": "CORE:C:0005", "count": 1}],
        },
        {"reason": listed_reason_text("unbacked"), "rules": [{"rule": "CORE:S:0002", "count": 2}]},
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_groups_listed_when_no_location_is_left():
    """A workflow with nothing left to rewrite still lists what stays open; that list is grouped
    the same way, so a reader of the bounded reply sees one shape either way."""
    payload = _workflow_payload(n_locations=1)
    del payload["workflow"]["locations"]
    payload["workflow"]["listed"] = [
        {"rule": "CORE:E:0004", "reason": "no-gain", "count": 40},
        {"rule": "CORE:C:0005", "reason": "no-gain", "count": 1},
    ]

    listed = bound_validate_payload(payload)["workflow"]["listed"]

    assert listed == [
        {
            "reason": listed_reason_text("no-gain"),
            "rules": [{"rule": "CORE:E:0004", "count": 40}, {"rule": "CORE:C:0005", "count": 1}],
        }
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_gives_an_unknown_reason_code_the_neutral_sentence():
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["listed"] = [{"rule": "CORE:E:0004", "reason": "brand-new-code", "count": 4}]

    listed = bound_validate_payload(payload)["workflow"]["listed"]

    assert listed == [{"reason": listed_reason_text("brand-new-code"), "rules": [{"rule": "CORE:E:0004", "count": 4}]}]
    assert listed_reason_text("brand-new-code") == listed_reason_text("another-new-code")
    assert listed_reason_text("brand-new-code") != listed_reason_text("no-gain")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_groups_listed_in_first_seen_reason_order():
    """Group order follows the first appearance of each distinct reason code, not sort order."""
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["listed"] = [
        {"rule": "CORE:S:0001", "reason": "unbacked", "count": 1},
        {"rule": "CORE:S:0002", "reason": "convention", "count": 1},
        {"rule": "CORE:S:0003", "reason": "unbacked", "count": 1},
    ]

    listed = bound_validate_payload(payload)["workflow"]["listed"]

    assert [group["reason"] for group in listed] == [listed_reason_text("unbacked"), listed_reason_text("convention")]
    assert [row["rule"] for row in listed[0]["rules"]] == ["CORE:S:0001", "CORE:S:0003"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_envelope_grouped_listed_every_rule_still_resolves_in_the_rules_map():
    """Grouping restructures `listed`, but every rule id it names must still surface to
    `with_rule_labels` so the top-level `rules` map still carries it."""
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["listed"] = [
        {"rule": "CORE:E:0004", "reason": "long", "count": 40},
        {"rule": "CORE:E:0003", "reason": "doc", "count": 1},
    ]

    bounded = bound_validate_payload(payload)

    assert {"CORE:E:0004", "CORE:E:0003"} <= set(bounded["rules"])


@pytest.mark.unit
@pytest.mark.subsys_server
def test_full_true_keeps_listed_ungrouped():
    """`full=true` never routes through `bound_validate_payload` (`server._run_validate`
    calls `with_rule_labels(payload)` directly for it) — `listed` stays the server's own
    per-rule rows (`rule`, `reason`, `count`), same shape as `-f json`."""
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["listed"] = [
        {"rule": "CORE:E:0004", "reason": "long", "count": 40},
        {"rule": "CORE:C:0005", "reason": "doc", "count": 1},
    ]

    full = with_rule_labels(payload)

    assert full["workflow"]["listed"] == payload["workflow"]["listed"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_targeted_workflow_keeps_each_kept_location_s_findings_and_relations():
    """A targeted `validate` (`workflow.targets` present) already kept only the few locations
    holding a targeted file — the bounded reply keeps those locations' `findings` and
    `relations` too, and keeps `workflow.targets` itself, so the remedy agent's per-element
    check reads them without a further round trip; an untargeted reply still drops them."""
    payload = _workflow_payload(n_locations=3)
    payload["workflow"]["targets"] = {"tokens": ["skills:skill-1"], "locations": [1], "of": 3}

    bounded = bound_validate_payload(payload)["workflow"]

    assert bounded["targets"] == {"tokens": ["skills:skill-1"], "locations": [1], "of": 3}
    for loc in bounded["locations"]:
        assert loc["findings"] == [
            {"rule": "CORE:C:0042", "file": loc["files"][0], "line": 1, "pi": 0, "message": "m", "remedy": "r"}
        ]
        assert loc["relations"] == []
        assert loc["finding_count"] == 1


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_untargeted_workflow_still_drops_findings_and_relations():
    """No `workflow.targets` — the untargeted (whole-project) shape — keeps the index-only
    behaviour: no `findings` / `relations` key survives on any location."""
    payload = _workflow_payload(n_locations=3)

    bounded = bound_validate_payload(payload)["workflow"]

    assert "targets" not in bounded
    for loc in bounded["locations"]:
        assert "findings" not in loc
        assert "relations" not in loc


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_targeted_view_of_one_location_keeps_detail():
    """A targeted view kept down to a single location stays small either way — detail stays."""
    payload = _workflow_payload(n_locations=1)
    payload["workflow"]["targets"] = {"tokens": ["skills:skill-1"], "locations": [1], "of": 1}

    bounded = bound_validate_payload(payload)["workflow"]

    for loc in bounded["locations"]:
        assert "findings" in loc
        assert "relations" in loc


def _large_targeted_payload(n_locations: int = 3, n_findings: int = 60) -> dict:
    """A targeted workflow whose locations each hold many findings, every one nesting members."""
    payload = _workflow_payload(n_locations=n_locations)
    payload["workflow"]["targets"] = {
        "tokens": ["skills"],
        "locations": list(range(1, n_locations + 1)),
        "of": n_locations,
    }
    for loc in payload["workflow"]["locations"]:
        loc["findings"] = [
            {
                "rule": "CORE:C:0058",
                "file": loc["files"][0],
                "line": n,
                "pi": n,
                "message": "x" * 150,
                "remedy": "y" * 150,
                "members": [
                    {
                        "rule": "CORE:C:0042",
                        "file": loc["files"][0],
                        "line": n,
                        "message": "m" * 100,
                        "remedy": "r" * 100,
                    }
                    for _ in range(3)
                ],
            }
            for n in range(n_findings)
        ]
    return payload


def _reply_size(reply: dict) -> int:
    return len(json.dumps({k: v for k, v in reply.items() if k != "rules"}, separators=(",", ":")))


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_targeted_reply_over_the_size_bar_is_index_only_and_points_at_remedy_brief():
    """Three targeted locations with many findings and nested members would run past 16,000
    characters; the reply stays under the bar without its `rules` map by serving the index,
    and the `truncated.hint` names the call that serves the findings."""
    payload = _large_targeted_payload()

    bounded = bound_validate_payload(payload)

    assert _reply_size(bounded) <= 16_000
    assert all("findings" not in loc and "relations" not in loc for loc in bounded["workflow"]["locations"])
    assert bounded["workflow"]["locations"][0]["finding_count"] == 60 * 4
    assert "remedy_brief(path, location, targets)" in bounded["truncated"]["hint"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_targeted_reply_inlines_detail_only_while_it_fits():
    """Many small targeted locations (more than three) still carry their findings while the
    reply fits the bar; the same locations grown past it drop to the index."""
    small = _workflow_payload(n_locations=6)
    small["workflow"]["targets"] = {"tokens": ["skills:*"], "locations": [1, 2, 3, 4, 5, 6], "of": 6}

    kept = bound_validate_payload(small)["workflow"]["locations"]

    assert all("findings" in loc and "relations" in loc for loc in kept)
    assert "remedy_brief(path, location, targets)" not in bound_validate_payload(small).get("truncated", {}).get(
        "hint", ""
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_targeted_view_with_no_files_or_cross_file_drops_detail_past_the_size_bar():
    """Targeting clean files that sit in served locations leaves `files` empty with no
    `cross_file` -- the envelope's early-return path must apply the same size bar."""
    payload = _large_targeted_payload()
    payload["files"] = {}

    bounded = bound_validate_payload(payload)

    assert _reply_size(bounded) <= 16_000
    assert all("findings" not in loc for loc in bounded["workflow"]["locations"])


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_oversize_targeted_reply_without_a_cut_list_still_names_remedy_brief():
    """A targeted reply too large to carry its findings stays an index, and `truncated.hint`
    names `remedy_brief` even when no other list was cut."""
    finding = {"rule": "CORE:C:0001", "file": "CLAUDE.md", "line": 1, "message": "m" * 400, "remedy": "r"}
    location = {
        "order": 1,
        "kind": "main",
        "element": "CLAUDE.md",
        "importance": "gate_mover",
        "files": ["CLAUDE.md"],
        "findings": [finding] * 200,
        "relations": [],
    }
    reply = bound_validate_payload(
        {"files": {}, "workflow": {"targets": {"tokens": ["@main"]}, "locations": [location]}}
    )
    assert "findings" not in reply["workflow"]["locations"][0]
    assert "remedy_brief" in reply["truncated"]["hint"]

"""The one walk over a parsed hook config: every handler with its event and matcher."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.utils.hook_config import hook_sites, value_at, walk_hooks

CLAUDE = {
    "hooks": {
        "PreToolUse": [
            {"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "a.sh"}, {"command": "b.sh"}]},
            {"hooks": []},
        ],
        "Stop": [{"hooks": [{"command": "c.sh"}]}],
    }
}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_grouped_walk_yields_each_handler_under_its_group_matcher() -> None:
    sites = list(walk_hooks(CLAUDE, block="hooks", grouped=True))
    assert [(s.event, s.matcher, s.handler["command"]) for s in sites] == [
        ("PreToolUse", "Edit|Write", "a.sh"),
        ("PreToolUse", "Edit|Write", "b.sh"),
        ("Stop", "", "c.sh"),
    ]
    assert sites[1].path == ("hooks", "PreToolUse", 0, "hooks", 1)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_direct_walk_reads_matcher_off_the_handler() -> None:
    data = {"version": 1, "hooks": {"preToolUse": [{"command": "x.sh", "matcher": "Read"}]}}
    (site,) = walk_hooks(data, block="hooks")
    assert (site.event, site.matcher, site.path) == ("preToolUse", "Read", ("hooks", "preToolUse", 0))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_named_hooks_walk_goes_one_level_down() -> None:
    data = {"guard": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"command": "g.sh"}]}]}}
    (site,) = walk_hooks(data, named_hooks=True, grouped=True)
    assert site.path == ("guard", "PreToolUse", 0, "hooks", 0)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "data",
    [
        {"hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"command": "a"}]}]}},
        {"guard": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"command": "a"}]}]}},
        {"PreToolUse": [{"matcher": "Edit", "hooks": [{"command": "a"}]}]},
    ],
)
def test_hook_sites_reads_any_agents_shape(data: dict) -> None:
    (site,) = hook_sites(data)
    assert (site.event, site.matcher, site.handler) == ("PreToolUse", "Edit", {"command": "a"})


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_file_that_is_not_an_object_has_no_hooks() -> None:
    assert list(hook_sites([1, 2])) == []
    assert list(hook_sites({"hooks": "nope"})) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_value_at_returns_none_off_the_path() -> None:
    assert value_at({"a": [1, {"b": 2}]}, ("a", 1, "b")) == 2
    assert value_at({"a": []}, ("a", 3)) is None

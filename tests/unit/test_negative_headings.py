"""Bare negative headings: the label set and the list items that sit under one."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.policy.negative_headings import in_negative_section, is_negative_heading


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "heading",
    [
        "Don'ts",
        "Dont",
        "Don\u2019ts",
        "DON'TS",
        "Do Not",
        "Do Nots",
        "Must Not",
        "Must NOTs",
        "Mustn't",
        "Never",
        "never:",
        "Shall Not",
        "Prohibited",
        "Forbidden",
        "  Must   Not  ",
    ],
)
def test_bare_negative_labels_match_whatever_the_punctuation_and_case(heading: str) -> None:
    assert is_negative_heading(heading)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "heading",
    ["Never use mocks", "Never Push Directly to Main", "Do's", "Must", "Always", "Testing", "", "Do not use mocks"],
)
def test_full_sentences_positive_labels_and_topics_do_not_match(heading: str) -> None:
    assert not is_negative_heading(heading)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("fmt", ["list", "numbered"])
def test_a_list_item_under_a_bare_negative_heading_is_in_the_section(fmt: str) -> None:
    assert in_negative_section("excitation", fmt, "Don'ts")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_only_list_items_under_a_negative_heading_are_in_the_section() -> None:
    assert not in_negative_section("excitation", "prose", "Don'ts")
    assert not in_negative_section("excitation", "table", "Don'ts")
    assert not in_negative_section("heading", "list", "Don'ts")
    assert not in_negative_section("excitation", "list", "Testing")
    assert not in_negative_section("excitation", "list", "Never use mocks")

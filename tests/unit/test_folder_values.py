"""The folder-value grammar: a folder name, or a folder path from the project root."""

from __future__ import annotations

from pathlib import Path, PurePath

import pytest

from reporails_cli.core.platform.policy.exclusion import (
    FolderValue,
    folder_value_problem,
    parse_folder_value,
)

ROOT = Path("/proj/root")
ROOTS = [ROOT]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("value", "parts", "anchored", "text"),
    [
        ("/docs", ("docs",), True, "./docs"),
        ("./docs", ("docs",), True, "./docs"),
        ("/proj/root/docs", ("docs",), True, "./docs"),
        ("docs/.", ("docs",), True, "./docs"),
        ("app/[id]", ("app", "[id]"), True, "app/[id]"),
        ("[slug]", ("[slug]",), False, "[slug]"),
        ("docs/", ("docs",), False, "docs"),
        ("docs", ("docs",), False, "docs"),
        ("pkg/docs", ("pkg", "docs"), True, "pkg/docs"),
        ("  pkg/docs  ", ("pkg", "docs"), True, "pkg/docs"),
        ("a..b", ("a..b",), False, "a..b"),
        ("...", ("...",), False, "..."),
    ],
)
def test_parse_accepted_values(value: str, parts: tuple[str, ...], anchored: bool, text: str) -> None:
    parsed = parse_folder_value(value, ROOTS)
    assert parsed == FolderValue(parts, anchored)
    assert parsed is not None
    assert parsed.text == text


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("value", ["", "/", ".", "./", "/proj/root", "/proj/root/"])
def test_parse_empty_values_are_nothing(value: str) -> None:
    assert parse_folder_value(value, ROOTS) is None


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("value", "holds"),
    [
        ("docs/*", "it holds '*'"),
        ("**/docs", "it holds '*'"),
        ("do?s", "it holds '?'"),
        ("docs\\x", "it holds a backslash"),
        ("../x", "it steps up with '..'"),
        ("a/../x", "it steps up with '..'"),
    ],
)
def test_refused_values(value: str, holds: str) -> None:
    problem = folder_value_problem(value)
    assert problem == f"'{value}' is not a folder name or a folder path: {holds}"
    with pytest.raises(ValueError, match="not a folder name"):
        parse_folder_value(value, ROOTS)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("value", ["docs", "app/[id]", "[slug]", "...", "a..b", "./docs", "/docs", "  docs  "])
def test_acceptable_values_have_no_problem(value: str) -> None:
    assert folder_value_problem(value) is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolved_root_prefix_is_dropped() -> None:
    roots: list[PurePath] = [Path("/link/root"), Path("/real/root")]
    assert parse_folder_value("/real/root/pkg/docs", roots) == FolderValue(("pkg", "docs"), True)
    assert parse_folder_value("/link/root/docs", roots) == FolderValue(("docs",), True)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_holds_name_matches_any_depth_and_anchored_only_the_prefix() -> None:
    name = FolderValue(("docs",))
    assert name.holds("a/docs/x.md")
    assert name.holds("docs")
    assert not name.holds("a/other/x.md")
    assert not name.holds("a/mydocs/x.md")
    anchored = FolderValue(("pkg", "docs"), True)
    assert anchored.holds("pkg/docs/x.md")
    assert anchored.holds("pkg/docs")
    assert not anchored.holds("a/pkg/docs/x.md")
    assert not anchored.holds("pkg")
    assert not name.holds("")


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("value", "inside", "outside"),
    [
        ("[slug]", ["[slug]", "app/[slug]/x.md"], ["s", "slug", "a/l/x.md", "app/slug/x.md"]),
        ("app/[id]", ["app/[id]", "app/[id]/x.md"], ["app/i", "app/d", "app/id/x.md", "x/app/[id]"]),
        ("{a,b}", ["{a,b}", "p/{a,b}/x.md"], ["a", "b", "p/a/x.md", "p/b/x.md", "a,b"]),
        ("a,b", ["a,b", "p/a,b/x.md"], ["a", "b", "p/a/x.md", "{a,b}"]),
        ("a-b.c", ["a-b.c/x.md"], ["axb.c/x.md"]),
    ],
)
def test_a_folder_value_holds_only_the_folder_it_spells(value: str, inside: list[str], outside: list[str]) -> None:
    folder = parse_folder_value(value, ROOTS)
    assert folder is not None
    assert all(folder.holds(rel) for rel in inside)
    assert not any(folder.holds(rel) for rel in outside)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("value", ["pkg/[id]", "pkg/{a,b}", "pkg/a,b"])
def test_an_anchored_folder_value_holds_only_the_path_it_spells(value: str) -> None:
    folder = parse_folder_value(value, ROOTS)
    assert folder is not None
    literal = value
    assert folder.holds(literal) and folder.holds(literal + "/x.md")
    assert not folder.holds("pkg/other") and not folder.holds("x/" + literal)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("parts", "anchored"),
    [((), False), ((), True), (("",), False), (("a", ""), True), (("a", "b"), False)],
)
def test_a_folder_value_it_cannot_honour_is_refused(parts: tuple[str, ...], anchored: bool) -> None:
    with pytest.raises(ValueError):
        FolderValue(parts, anchored)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_name_or_anchored_path_is_admitted() -> None:
    assert FolderValue(("docs",)).holds("docs")
    assert FolderValue(("a", "b"), True).holds("a/b")

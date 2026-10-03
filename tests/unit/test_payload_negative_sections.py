"""The `ns` request key on atoms the real mapper reads out of a file: set on a bare negative
heading and on a list item directly under one, absent everywhere else."""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.core.platform.adapters.payload import project_payload

try:
    from reporails_cli.core.mapper.bio_tagger import multislot_available

    _requires_model = pytest.mark.skipif(not multislot_available(), reason="Bundled charge-model graphs not available")
except ImportError:  # pragma: no cover - mapper extras not installed
    _requires_model = pytest.mark.skip(reason="mapper extras not installed")

_ITEMS = "- Use mock objects in tests.\n- Use test doubles in the suite.\n"


def _projected(tmp_path, text: str, extra: dict[str, str] | None = None) -> list[tuple[str, bool]]:
    """(atom text, `ns` set) for every atom of the mapped file, in the payload's own order."""
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    target = tmp_path / "CLAUDE.md"
    target.write_text(text, encoding="utf-8")
    for name, body in (extra or {}).items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    ruleset = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    payload = project_payload(ruleset, tmp_path)
    atoms = [a for a in ruleset.atoms if a.role != "list_object"]
    wire: list[dict[str, Any]] = payload["atoms"]
    assert len(atoms) == len(wire)
    return [(a.text, bool(w.get("ns", False))) for a, w in zip(atoms, wire, strict=True)]


def _flags(rows: list[tuple[str, bool]], *texts: str) -> list[bool]:
    by_text = dict(rows)
    return [by_text[t] for t in texts]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_an_atx_negative_heading_and_its_list_items_carry_ns(tmp_path) -> None:
    rows = _projected(tmp_path, f"# Project\n\n## Don'ts\n\n{_ITEMS}")
    assert _flags(rows, "Project", "Don'ts") == [False, True]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_setext_negative_heading_and_its_list_items_carry_ns(tmp_path) -> None:
    rows = _projected(tmp_path, f"Project\n=======\n\nDon'ts\n------\n\n{_ITEMS}")
    assert _flags(rows, "Don'ts") == [True]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_blockquoted_negative_heading_and_its_list_items_carry_ns(tmp_path) -> None:
    quoted = "".join(f"> {line}\n" for line in _ITEMS.splitlines())
    rows = _projected(tmp_path, f"# Project\n\n> ## Never\n>\n{quoted}")
    assert _flags(rows, "Never") == [True]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_numbered_list_under_a_negative_heading_carries_ns(tmp_path) -> None:
    rows = _projected(
        tmp_path,
        "# Project\n\n## Don'ts\n\n1. Use mock objects in tests.\n2. Use test doubles in the suite.\n",
    )
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_nested_list_item_under_a_negative_heading_carries_ns(tmp_path) -> None:
    rows = _projected(
        tmp_path,
        "# Project\n\n## Don'ts\n\n- Use mock objects in tests.\n"
        "  - Use test doubles in the suite.\n- Commit secrets.\n",
    )
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.", "Commit secrets.") == [
        True,
        True,
        True,
    ]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_prose_line_between_the_heading_and_the_list_has_no_ns_but_the_list_keeps_it(tmp_path) -> None:
    rows = _projected(
        tmp_path,
        f"# Project\n\n## Don'ts\n\nThese are the rules we keep here.\n\n{_ITEMS}",
    )
    assert _flags(rows, "These are the rules we keep here.") == [False]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_list_item_under_a_sub_heading_inside_the_section_has_no_ns(tmp_path) -> None:
    rows = _projected(tmp_path, f"# Project\n\n## Don'ts\n\n### Testing\n\n{_ITEMS}")
    assert _flags(rows, "Don'ts", "Testing") == [True, False]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [False, False]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_list_item_in_an_imported_file_under_a_negative_heading_carries_ns(tmp_path) -> None:
    rows = _projected(
        tmp_path,
        "# Project\n\n@rules.md\n",
        extra={"rules.md": f"## Don'ts\n\n{_ITEMS}"},
    )
    assert _flags(rows, "Don'ts") == [True]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [True, True]


@pytest.mark.integration
@pytest.mark.subsys_server
@_requires_model
def test_a_full_sentence_heading_and_its_list_items_have_no_ns(tmp_path) -> None:
    rows = _projected(tmp_path, f"# Project\n\n## Do not use mock objects in tests\n\n{_ITEMS}")
    assert _flags(rows, "Do not use mock objects in tests") == [False]
    assert _flags(rows, "Use mock objects in tests.", "Use test doubles in the suite.") == [False, False]

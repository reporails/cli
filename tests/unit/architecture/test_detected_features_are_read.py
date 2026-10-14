"""Every field of the detected-features records is read by code that is neither the module that
defines it nor the detector that fills it; a field nothing reads is detection work for no one."""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto import results

SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "reporails_cli"
_WRITERS = {SRC / "core" / "platform" / "dto" / "results.py", SRC / "core" / "discovery" / "features.py"}
_RECORDS = (
    results.DetectedFeatures,
    results.DiscoveryFeatures,
    results.MemoryFeatures,
)


def _consumes_features(tree: ast.AST) -> bool:
    """True when the module imports the features record or a feature detector."""
    return any(
        a.name == "DetectedFeatures" or a.name.startswith("detect_features")
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for a in node.names
    )


def _attributes_read_outside_writers(sources: list[Path] | None = None) -> set[str]:
    """Attribute names read in modules that consume the features record, writers excluded."""
    names: set[str] = set()
    for py in sources if sources is not None else sorted(SRC.rglob("*.py")):
        if py in _WRITERS:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        if _consumes_features(tree):
            names.update(node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute))
    return names


def _unread_fields(read: set[str], records: tuple[type, ...] = _RECORDS) -> list[str]:
    return [
        f"{record.__name__}.{field.name}"
        for record in records
        for field in dataclasses.fields(record)
        if field.name not in read
    ]


@pytest.mark.architecture
def test_every_detected_feature_field_is_read_somewhere() -> None:
    """A field no code reads is removed together with the detection that fills it."""
    unread = _unread_fields(_attributes_read_outside_writers())
    assert not unread, f"fields nothing outside their defining module and detector reads: {unread}"


@pytest.mark.architecture
def test_a_same_named_attribute_in_an_unrelated_module_is_not_a_read(tmp_path: Path) -> None:
    """`result.hooks` in a module that never touches the features record does not count."""
    unrelated = tmp_path / "unrelated.py"
    unrelated.write_text("def f(result):\n    return result.hooks\n", encoding="utf-8")
    consumer = tmp_path / "consumer.py"
    consumer.write_text(
        "from reporails_cli.core.platform.dto.results import DetectedFeatures\n"
        "def f(features: DetectedFeatures):\n    return features.hooks\n",
        encoding="utf-8",
    )
    assert "hooks" not in _attributes_read_outside_writers([unrelated])
    assert "hooks" in _attributes_read_outside_writers([unrelated, consumer])

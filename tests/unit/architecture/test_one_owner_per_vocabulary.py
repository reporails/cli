"""One owner per closed string vocabulary.

A vocabulary is a module-level `Name = Literal["a", ...]` alias (or `Name: TypeAlias = Literal[...]`,
or `type Name = Literal[...]`) or a `class X(str, Enum)` / `StrEnum` in `src/reporails_cli/`. The
module that defines it is the owner, and every named subgroup of its members lives beside it.

Four rules, all pure `ast`:

- A1 private group: a string-collection literal (set, tuple or list display, `frozenset(...)` /
  `set(...)` / `tuple(...)` / `list(...)` of one literal, or the members of an inline `Literal[...]`)
  with at least two distinct members, outside the owner module, whose members all belong to one
  vocabulary. Import the owner's named group, or add the group beside the owner. For a `str`-Enum /
  `StrEnum` vocabulary a string group or a dict keyed by the members' string values fails anywhere,
  the owner module included: use a group of members, a dict keyed by members, or `X(value)`. Dict
  displays over a `Literal` vocabulary are not groups (mypy checks their keys).
- A2 unowned shared group: two such literals in different modules that share at least two members
  while one contains the other, or whose Jaccard similarity is above 0.5. The shared members
  belong in one named group in one module. `__all__` and dict displays are not compared.
- A3 sentence mark: a regex holding a character class of exactly `.`, `!`, `?` (optionally with an
  ellipsis) anywhere outside `core/mapper/prose_split.py`, which owns sentence splitting.
- A4 duplicate pattern: the same regex source (eight or more characters) compiled in two modules.
  One module owns the pattern; the other imports it.

Why: a concept spelled out twice drifts apart, and the copy that is not updated silently
disagrees with its owner.

Each scanner takes the source files and their root, so the planted tests below run the same code
on tmp files. `_ALLOWLIST` is keyed by violation key and carries the reason a violation is
accepted; it starts empty.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
SENTENCE_OWNER = "core/mapper/prose_split.py"

_ALLOWLIST: dict[str, str] = {}

_GROUP_CALLS = {"frozenset", "set", "tuple", "list"}
_RE_FUNCS = {"compile", "search", "match", "fullmatch", "sub", "subn", "split", "findall", "finditer"}
_ELLIPSIS = "\u2026"
_SENTENCE_CLASS = {".", "!", "?"}
_MIN_PATTERN = 8
_CHAR_CLASS = re.compile(r"\[(\^?)((?:\\.|[^\]\\])+)\]")


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule, a stable allowlist key, and a human reason."""

    rule: str
    key: str
    detail: str


@dataclass(frozen=True)
class Vocabulary:
    """A closed string vocabulary and the module that owns it."""

    name: str
    owner: str
    members: frozenset[str]
    enum: bool = False


@dataclass(frozen=True)
class Group:
    """A string-collection literal at `module:line`."""

    module: str
    line: int
    members: frozenset[str]
    is_dict: bool = False

    @property
    def site(self) -> str:
        """The `module:line` location."""
        return f"{self.module}:{self.line}"


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


@cache
def _parse_cached(path: Path, mtime_ns: int) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parse(path: Path) -> ast.Module:
    return _parse_cached(path, path.stat().st_mtime_ns)


def _string_elements(elts: Iterable[ast.expr]) -> list[str] | None:
    out: list[str] = []
    for elt in elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            return None
    return out


def _display_members(node: ast.AST) -> list[str] | None:
    """Members of a set/tuple/list display of string constants (or a dict display's keys), else None."""
    if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        return _string_elements(node.elts)
    if isinstance(node, ast.Dict):
        return _string_elements([k if k is not None else ast.Pass() for k in node.keys])
    return None


def _literal_args(node: ast.expr) -> list[str] | None:
    """String arguments of a `Literal[...]` subscript, else None."""
    if not isinstance(node, ast.Subscript):
        return None
    base = node.value
    name = base.id if isinstance(base, ast.Name) else base.attr if isinstance(base, ast.Attribute) else ""
    if name != "Literal":
        return None
    args = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
    return _string_elements(args)


def _vocabulary_value(node: ast.stmt) -> tuple[str, ast.expr] | None:
    """(name, value) for a module-level alias statement."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    if isinstance(node, ast.TypeAlias):
        return node.name.id, node.value
    return None


def _enum_members(node: ast.ClassDef) -> list[str] | None:
    bases = {ast.unparse(b).split(".")[-1] for b in node.bases}
    if "StrEnum" not in bases and not {"str", "Enum"} <= bases:
        return None
    out: list[str] = []
    for stmt in node.body:
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            out.append(value.value)
    return out


def _vocabulary_definitions(tree: ast.Module) -> Iterator[tuple[str, list[str], ast.AST]]:
    """(name, members, defining node) of each vocabulary a module defines."""
    for node in tree.body:
        pair = _vocabulary_value(node)
        if pair is not None:
            members = _literal_args(pair[1])
            if members:
                yield pair[0], members, pair[1]
        elif isinstance(node, ast.ClassDef):
            members = _enum_members(node)
            if members:
                yield node.name, members, node


def collect_vocabularies(sources: list[Path], root: Path) -> list[Vocabulary]:
    """Every closed string vocabulary defined in `sources`, owned by its defining module."""
    return [
        Vocabulary(name, _rel(py, root), frozenset(members), isinstance(definition, ast.ClassDef))
        for py in sources
        for name, members, definition in _vocabulary_definitions(_parse(py))
    ]


def _group_members(node: ast.AST) -> tuple[list[str], ast.AST] | None:
    """Members of a string-collection literal rooted at `node`, plus the node that carries them."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _GROUP_CALLS:
        if len(node.args) == 1 and not node.keywords:
            members = _display_members(node.args[0])
            if members is not None:
                return members, node.args[0]
        return None
    members = _display_members(node)
    if members is not None:
        return members, node
    members = _literal_args(node) if isinstance(node, ast.Subscript) else None
    if members is not None and isinstance(node, ast.Subscript):
        return members, node.slice
    return None


def collect_groups(sources: list[Path], root: Path) -> list[Group]:
    """Every string-collection literal with two or more distinct members, owned definitions excluded."""
    groups: list[Group] = []
    for py in sources:
        tree = _parse(py)
        skip: set[int] = {id(definition) for _, _, definition in _vocabulary_definitions(tree)}
        consumed: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
                    skip.add(id(node.value))
            if id(node) in skip:
                if isinstance(node, ast.Subscript):
                    skip.add(id(node.slice))
                continue
            if id(node) in consumed:
                continue
            found = _group_members(node)
            if found is None:
                continue
            members, inner = found
            consumed.add(id(inner))
            if id(inner) in skip or len(set(members)) < 2:
                continue
            groups.append(
                Group(_rel(py, root), getattr(node, "lineno", 0), frozenset(members), isinstance(node, ast.Dict))
            )
    return groups


def private_group_violations(sources: list[Path], root: Path, groups: list[Group] | None = None) -> list[Violation]:
    """A1: a group inside one vocabulary, outside its owner; for enum vocabularies anywhere, dicts included."""
    vocabularies = collect_vocabularies(sources, root)
    out: list[Violation] = []
    for group in groups if groups is not None else collect_groups(sources, root):
        matches = [
            v
            for v in vocabularies
            if group.members <= v.members and (v.enum or (v.owner != group.module and not group.is_dict))
        ]
        if not matches:
            continue
        vocab = min(matches, key=lambda v: (len(v.members), v.name))
        out.append(
            Violation(
                "A1",
                f"A1 {group.site}",
                f"{group.site} holds {sorted(group.members)}, a subset of vocabulary {vocab.name} "
                f"owned by {vocab.owner}",
            )
        )
    return out


def shared_group_violations(sources: list[Path], root: Path, groups: list[Group] | None = None) -> list[Violation]:
    """A2: two groups in different modules where one contains the other or most members are shared."""
    groups = [g for g in (groups if groups is not None else collect_groups(sources, root)) if not g.is_dict]
    out: list[Violation] = []
    for i, left in enumerate(groups):
        for right in groups[i + 1 :]:
            if left.module == right.module:
                continue
            shared = left.members & right.members
            if len(shared) < 2:
                continue
            nested = shared in (left.members, right.members)
            if nested or len(shared) / len(left.members | right.members) > 0.5:
                first, second = sorted((left, right), key=lambda g: (g.module, g.line))
                out.append(
                    Violation(
                        "A2",
                        f"A2 {first.site} ~ {second.site}",
                        f"{first.site} and {second.site} share {sorted(shared)} with no single owner",
                    )
                )
    return out


def _regex_calls(tree: ast.Module) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.func.attr in _RE_FUNCS
            and node.args
        ):
            yield node


def _string_parts(node: ast.expr) -> list[str]:
    """String parts of a literal, an f-string or a concatenation of those."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _string_parts(node.left) + _string_parts(node.right)
    return []


def _class_members(body: str) -> set[str]:
    text = body.replace("\\u2026", _ELLIPSIS)
    members: set[str] = set()
    index = 0
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            index += 1
        members.add(text[index])
        index += 1
    return members


def _is_sentence_class(part: str) -> bool:
    for negated, body in _CHAR_CLASS.findall(part):
        if negated:
            continue
        members = _class_members(body)
        if members - {_ELLIPSIS} == _SENTENCE_CLASS:
            return True
    return False


def sentence_mark_violations(sources: list[Path], root: Path, owner: str = SENTENCE_OWNER) -> list[Violation]:
    """A3: a regex character class of exactly the sentence marks outside the sentence owner."""
    out: list[Violation] = []
    for py in sources:
        rel = _rel(py, root)
        if rel == owner:
            continue
        for call in _regex_calls(_parse(py)):
            if any(_is_sentence_class(part) for part in _string_parts(call.args[0])):
                site = f"{rel}:{call.lineno}"
                out.append(
                    Violation("A3", f"A3 {site}", f"{site} spells the sentence marks in a regex; {owner} owns them")
                )
    return out


def duplicate_pattern_violations(sources: list[Path], root: Path) -> list[Violation]:
    """A4: the same regex source compiled in two different modules."""
    sites: dict[str, list[str]] = {}
    for py in sources:
        rel = _rel(py, root)
        for call in _regex_calls(_parse(py)):
            arg = call.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) >= _MIN_PATTERN:
                sites.setdefault(arg.value, []).append(f"{rel}:{call.lineno}")
    out: list[Violation] = []
    for pattern, where in sorted(sites.items()):
        if len({site.rsplit(":", 1)[0] for site in where}) > 1:
            out.append(Violation("A4", f"A4 {pattern}", f"pattern {pattern!r} appears in {', '.join(where)}"))
    return out


def vocabulary_violations(sources: list[Path], root: Path) -> list[Violation]:
    """All four rules over `sources`, allowlisted keys removed."""
    groups = collect_groups(sources, root)
    found = [
        *private_group_violations(sources, root, groups),
        *shared_group_violations(sources, root, groups),
        *sentence_mark_violations(sources, root),
        *duplicate_pattern_violations(sources, root),
    ]
    return [v for v in found if v.key not in _ALLOWLIST]


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def _format(violations: list[Violation]) -> str:
    lines = [f"{len(violations)} vocabulary-ownership violation(s):"]
    for rule in ("A1", "A2", "A3", "A4"):
        mine = [v for v in violations if v.rule == rule]
        lines.append(f"{rule}: {len(mine)}")
        lines.extend(f"  {v.detail}" for v in mine)
    lines.append("Import the owner's named group; add a group beside the owner; or allowlist with a reason.")
    return "\n".join(lines)


@pytest.mark.architecture
def test_every_vocabulary_has_one_owner() -> None:
    """No private copy, unowned shared group, stray sentence-mark class or duplicate pattern in src."""
    violations = vocabulary_violations(_src_files(), SRC)
    assert not violations, _format(violations)


# ---- planted cases -------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


_VOCAB = (
    "from typing import Literal\n"
    'Fmt = Literal["prose", "list", "numbered", "table"]\n'
    'LISTY: frozenset[str] = frozenset({"list", "numbered"})\n'
)


@pytest.mark.architecture
def test_a1_private_subset_of_a_vocabulary_fires(tmp_path: Path) -> None:
    """A set of vocabulary members outside the owner is flagged; the owner's own group is not."""
    sources = _plant(
        tmp_path,
        {
            "vocab.py": _VOCAB,
            "red.py": 'KINDS = {"prose", "list"}\n',
            "red_literal.py": 'from typing import Literal\ndef f(x: Literal["prose", "table"]) -> None: ...\n',
        },
    )
    found = private_group_violations(sources, tmp_path)
    assert {v.key for v in found} == {"A1 red.py:1", "A1 red_literal.py:2"}
    assert "Fmt" in found[0].detail and "vocab.py" in found[0].detail


_ENUM = 'from enum import StrEnum\nclass InstallMethod(StrEnum):\n    NPM = "npm"\n    NPX = "npx"\n    UV = "uv"\n'


@pytest.mark.architecture
def test_a1_dict_keyed_by_vocabulary_values_fires(tmp_path: Path) -> None:
    """A string-keyed dict over a StrEnum's values fires inside and outside the enum's module."""
    sources = _plant(
        tmp_path,
        {
            "vocab.py": _VOCAB,
            "install.py": _ENUM + '_LAUNCHERS = {"npm": InstallMethod.NPM, "npx": InstallMethod.NPX}\n',
            "red.py": 'from install import InstallMethod\nT = {"npm": 1, "uv": 2}\n',
        },
    )
    found = private_group_violations(sources, tmp_path)
    assert {v.key for v in found} == {"A1 red.py:2", "A1 install.py:6"}


@pytest.mark.architecture
def test_a1_stays_quiet_on_member_keys_literal_tables_and_constructor(tmp_path: Path) -> None:
    """Member-keyed dicts, string-keyed tables over a Literal vocabulary and `X(value)` pass."""
    sources = _plant(
        tmp_path,
        {
            "vocab.py": _VOCAB + 'RANK = {"prose": 0, "list": 1}\n',
            "install.py": (
                _ENUM + "RANK = {InstallMethod.NPM: 1, InstallMethod.NPX: 2}\n"
                "GROUP = frozenset({InstallMethod.NPM, InstallMethod.NPX})\n"
                "def parse(value: str) -> InstallMethod:\n    return InstallMethod(value)\n"
            ),
            "other.py": (
                "from install import InstallMethod\nT = {InstallMethod.NPM: 1, InstallMethod.UV: 2}\n"
                'LITERAL_TABLE = {"prose": 1, "table": 2}\n'
            ),
        },
    )
    assert private_group_violations(sources, tmp_path) == []


@pytest.mark.architecture
def test_a1_stays_quiet_on_owner_group_and_unrelated_sets(tmp_path: Path) -> None:
    """The owner's subgroup, a group with a foreign member, a one-member set and a foreign-keyed dict pass."""
    sources = _plant(
        tmp_path,
        {
            "vocab.py": _VOCAB,
            "green.py": (
                'OTHER = {"prose", "unrelated"}\nSINGLE = {"prose"}\n'
                'MAP = {"prose": 1, "unrelated": 2}\n'
                "from vocab import LISTY\nUSES = LISTY\n"
            ),
        },
    )
    assert private_group_violations(sources, tmp_path) == []


_RED_SET = 'A = {"alpha", "beta", "gamma"}\n'


@pytest.mark.architecture
def test_a2_unowned_shared_group_fires_once_per_pair(tmp_path: Path) -> None:
    """Nested and mostly-overlapping groups in different modules fire, one entry per pair."""
    sources = _plant(
        tmp_path,
        {
            "one.py": _RED_SET,
            "two.py": 'B = ("alpha", "beta", "gamma", "delta")\n',
            "three.py": 'C = frozenset(["alpha", "beta", "gamma", "epsilon"])\n',
        },
    )
    found = shared_group_violations(sources, tmp_path)
    assert {v.key for v in found} == {
        "A2 one.py:1 ~ two.py:1",
        "A2 one.py:1 ~ three.py:1",
        "A2 three.py:1 ~ two.py:1",
    }


@pytest.mark.architecture
def test_a2_stays_quiet_on_disjoint_same_module_and_dicts(tmp_path: Path) -> None:
    """Disjoint groups, two overlapping groups in one module, `__all__` and dict displays pass."""
    sources = _plant(
        tmp_path,
        {
            "one.py": _RED_SET + 'B = {"alpha", "beta"}\n',
            "two.py": 'C = {"x1", "x2", "x3"}\n__all__ = ["alpha", "beta", "gamma"]\n',
            "three.py": 'D = {"alpha": 1, "beta": 2, "gamma": 3}\n',
            "four.py": 'E = {"alpha", "z1", "z2", "z3", "z4"}\n',
        },
    )
    assert shared_group_violations(sources, tmp_path) == []


@pytest.mark.architecture
def test_a3_sentence_mark_class_fires_outside_the_owner(tmp_path: Path) -> None:
    """`[.!?]`, an escaped form, an ellipsis variant and an f-string part fire in any other module."""
    sources = _plant(
        tmp_path,
        {
            "core/mapper/prose_split.py": 'import re\nOWN = re.compile(r"[.!?]")\n',
            "red.py": (
                "import re\n"
                'A = re.compile(r"(?<=[.!?])\\s+")\n'
                'B = re.split(r"[\\.\\!\\?\u2026]", "x")\n'
                'C = re.compile(rf"x{1}" + r"[?!.]")\n'
            ),
        },
    )
    found = sentence_mark_violations(sources, tmp_path)
    assert {v.key for v in found} == {"A3 red.py:2", "A3 red.py:3", "A3 red.py:4"}


@pytest.mark.architecture
def test_a3_stays_quiet_on_other_classes(tmp_path: Path) -> None:
    """Classes with other members, a negated class and a non-regex string pass."""
    sources = _plant(
        tmp_path,
        {
            "green.py": (
                "import re\n"
                'A = re.compile(r"[.!?;]")\nB = re.compile(r"[^.!?]+")\nC = re.compile(r"[.!]")\n'
                'D = "[.!?]"\n'
            ),
        },
    )
    assert sentence_mark_violations(sources, tmp_path) == []


@pytest.mark.architecture
def test_a4_same_pattern_in_two_modules_fires(tmp_path: Path) -> None:
    """One identical long pattern compiled in two modules is reported once, naming both sites."""
    sources = _plant(
        tmp_path,
        {
            "one.py": 'import re\nX = re.compile(r"^\\s*[-*]\\s+\\w+")\n',
            "two.py": 'import re\ndef f(s):\n    return re.search(r"^\\s*[-*]\\s+\\w+", s)\n',
        },
    )
    found = duplicate_pattern_violations(sources, tmp_path)
    assert len(found) == 1 and "one.py:2" in found[0].detail and "two.py:3" in found[0].detail


@pytest.mark.architecture
def test_a4_stays_quiet_on_short_distinct_or_same_module_patterns(tmp_path: Path) -> None:
    """Short patterns, distinct patterns and a repeat inside one module pass."""
    sources = _plant(
        tmp_path,
        {
            "one.py": (
                'import re\nA = re.compile(r"\\d+")\n'
                'B = re.compile(r"^\\s*[-*]\\s+\\w+")\nC = re.compile(r"^\\s*[-*]\\s+\\w+")\n'
            ),
            "two.py": 'import re\nA = re.compile(r"\\d+")\nB = re.compile(r"^\\s*[0-9]+\\.\\s+\\w+")\n',
        },
    )
    assert duplicate_pattern_violations(sources, tmp_path) == []


@pytest.mark.architecture
def test_vocabularies_include_aliases_type_statements_and_str_enums(tmp_path: Path) -> None:
    """`Literal` aliases, `TypeAlias`, `type` statements and str enums are all vocabularies."""
    sources = _plant(
        tmp_path,
        {
            "vocab.py": (
                "from enum import Enum, StrEnum\nfrom typing import Literal, TypeAlias\n"
                'A = Literal["a1", "a2"]\nB: TypeAlias = Literal["b1", "b2"]\ntype C = Literal["c1", "c2"]\n'
                'class D(str, Enum):\n    X = "d1"\n    Y = "d2"\n'
                'class E(StrEnum):\n    X = "e1"\n    Y = "e2"\n'
            ),
        },
    )
    assert {v.name: v.members for v in collect_vocabularies(sources, tmp_path)} == {
        "A": frozenset({"a1", "a2"}),
        "B": frozenset({"b1", "b2"}),
        "C": frozenset({"c1", "c2"}),
        "D": frozenset({"d1", "d2"}),
        "E": frozenset({"e1", "e2"}),
    }

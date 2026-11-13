"""The mapper owns reading instruction text: no copy at its address, no re-derivation beside it.

The mapper parses each file once and records what it read on every `Atom` (`plain_text`,
`named_tokens`, `lead_in`, `format`, `list_depth`, `heading_context`, `charge`, `modality`,
`scope_conditional`). A consumer reads those fields. Three rules, all pure `ast`:

- T1 copy at the mapper's address: a module-level word or punctuation definition in
  `core/mapper/` that the map itself never reaches. Reach starts at every definition of
  `MAP_ENTRY` and follows each name a reached definition reads, across modules. A word list,
  a prose regex or a punctuation string the map never reads is another subsystem's reading
  housed under the mapper's name. Delete it and read the `Atom` field, or make the map read it.
  The modules whose readers exist for every consumer (`READER_MODULES`: the markdown parser
  and the sentence splitter) are not held to reach.
- T2 markup handled outside the parser: a markdown markup literal (a backtick, or `*` together
  with `_`) passed to a strip, split, replace or translate call, or a module-level string
  constant holding one passed by name, outside `READER_MODULES`. `Atom.plain_text`,
  `named_tokens` and `parse.inline_plain_text` already carry the text without its markup.
- T3 re-derivation outside the mapper: a word collection (lowercase words, one of them an
  English function word), a prose regex (a dash, a clause-punctuation class, a word
  alternation, a word set joined into a pattern, a bare word tokenizer) or a split on a
  dash or a conjunction, in `core/` outside `core/mapper/`. `Literal[...]` arguments are the
  vocabulary floor's (`test_one_owner_per_vocabulary.py`).

Why: a consumer that reads the words again reaches its own verdict on text the score read
differently, and every new case grows another arm. Known limits: a prose split on `,`, `;` or
`:` is not read (configuration values and rule ids split on the same marks); a word set with
no function word (`{"example", "instance"}`) reads as an identifier vocabulary; a pattern held
outside a module-level string constant is not resolved; `formatters/` and `interfaces/`, which
word the cli's own messages, are not read by T3; T1 counts any map reader as reach, so a mapper
step built only to re-derive a reading for an outer consumer (re-finding an atom's text in its
line after the map is built) makes the data it reads look owned — review catches that, not
this floor. There is no allowlist.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
PACKAGE = "reporails_cli"
CORE = "core/"
MAPPER = "core/mapper/"
MAP_ENTRY = ("core/mapper/pipeline.py", "core/mapper/daemon_server.py")
READER_MODULES = frozenset(
    {
        "core/mapper/md_parser.py",
        "core/mapper/markdown_extract.py",
        "core/mapper/markers.py",
        "core/mapper/parse.py",
        "core/mapper/structure.py",
        "core/mapper/prose_split.py",
    }
)

# English function words: articles, pronouns, prepositions, conjunctions, modals, quantifiers.
FUNCTION_WORDS = frozenset(
    [
        "a",
        "an",
        "the",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "they",
        "them",
        "their",
        "he",
        "she",
        "we",
        "you",
        "your",
        "i",
        "me",
        "my",
        "our",
        "us",
        "of",
        "in",
        "on",
        "at",
        "by",
        "for",
        "with",
        "without",
        "within",
        "from",
        "to",
        "into",
        "onto",
        "over",
        "under",
        "about",
        "above",
        "below",
        "across",
        "after",
        "before",
        "between",
        "through",
        "during",
        "until",
        "till",
        "since",
        "except",
        "excluding",
        "outside",
        "beyond",
        "among",
        "against",
        "along",
        "around",
        "behind",
        "beside",
        "besides",
        "near",
        "per",
        "via",
        "than",
        "unlike",
        "like",
        "and",
        "or",
        "nor",
        "but",
        "yet",
        "so",
        "if",
        "unless",
        "when",
        "whenever",
        "while",
        "whilst",
        "where",
        "wherever",
        "whether",
        "because",
        "although",
        "though",
        "otherwise",
        "then",
        "not",
        "never",
        "only",
        "even",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "am",
        "do",
        "does",
        "did",
        "has",
        "have",
        "had",
        "can",
        "could",
        "may",
        "might",
        "must",
        "shall",
        "should",
        "will",
        "would",
        "all",
        "any",
        "each",
        "every",
        "some",
        "many",
        "most",
        "much",
        "few",
        "less",
        "least",
        "both",
        "either",
        "neither",
        "such",
        "e",
        "g",
        "eg",
        "ie",
        "i.e.",
        "e.g.",
        "etc",
    ]
)
_WORD = re.compile(r"^[a-z]+(?:[ '.-][a-z]+)*\.?$")
_MARK_CALLS = frozenset(
    {
        "strip",
        "lstrip",
        "rstrip",
        "split",
        "rsplit",
        "replace",
        "translate",
        "maketrans",
        "removeprefix",
        "removesuffix",
    }
)
_SPLIT_CALLS = frozenset({"split", "rsplit", "partition", "rpartition"})
_PROSE_SPLITS = frozenset({"\u2014", "\u2013", " \u2014 ", " \u2013 ", " - ", " and ", " or ", " then "})
_RE_MODULES = frozenset({"re", "regex"})
_RE_FUNCS = frozenset({"compile", "search", "match", "fullmatch", "sub", "subn", "split", "findall", "finditer"})
_SET_OPS = (ast.BitOr, ast.BitAnd, ast.Sub)
_CLAUSE_MARKS = frozenset(",;:")
_DASHES = ("\u2014", "\u2013", "\\u2014", "\\u2013")
_CHAR_CLASS = re.compile(r"\[(\^?)((?:\\.|[^\]\\])+)\]")
_WORD_ALTERNATION = re.compile(r"\\b\(\?:[a-z]{2,}(?:\\s\+|\s)?[a-z]*\|[a-z]{2,}|\\b\([a-z]{2,}\|[a-z]{2,}")
_WORD_TOKENIZER = re.compile(r"^(?:\\w|\[(?:a-z|A-Z|0-9|_|'|\\w)+\])\+$")


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule, its `module:line` site and what to do."""

    rule: str
    site: str
    detail: str


@cache
def _parse_cached(path: Path, mtime_ns: int) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parse(path: Path) -> ast.Module:
    return _parse_cached(path, path.stat().st_mtime_ns)


def _modules(sources: list[Path], root: Path) -> dict[str, ast.Module]:
    return {p.relative_to(root).as_posix(): _parse(p) for p in sources}


def _module_name(rel: str) -> str:
    return f"{PACKAGE}." + rel[:-3].replace("/", ".").removesuffix(".__init__")


def _import_base(rel: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    parts = _module_name(rel).split(".")
    if not rel.endswith("__init__.py"):
        parts = parts[:-1]
    parts = parts[: len(parts) - (node.level - 1)]
    return ".".join([*parts, *([node.module] if node.module else [])])


def _top_definitions(tree: ast.Module) -> dict[str, ast.stmt]:
    out: dict[str, ast.stmt] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = node
        elif isinstance(node, ast.Assign):
            out.update({t.id: node for t in node.targets if isinstance(t, ast.Name)})
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out[node.target.id] = node
    return out


def _string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level names bound to one string literal (or a concatenation of literals)."""
    out: dict[str, str] = {}
    for name, node in _top_definitions(tree).items():
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if value is not None:
            parts = _literal_parts(value, {})
            if parts is not None:
                out[name] = "".join(parts)
    return out


def _literal_parts(node: ast.expr, constants: dict[str, str]) -> list[str] | None:
    """The string parts of a literal, f-string, concatenation or resolved constant; None if not text."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
    if isinstance(node, ast.Name) and node.id in constants:
        return [constants[node.id]]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_parts(node.left, constants), _literal_parts(node.right, constants)
        if left is None and right is None:
            return None
        return [*(left or []), *(right or [])]
    return None


def _collection_strings(node: ast.AST) -> list[str] | None:
    """Members of a set/tuple/list display (or `frozenset(...)` of one) when all are strings."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"frozenset", "set", "tuple", "list"}
    ):
        return _collection_strings(node.args[0]) if len(node.args) == 1 and not node.keywords else None
    if not isinstance(node, (ast.Set, ast.Tuple, ast.List)) or not node.elts:
        return None
    out = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return out if len(out) == len(node.elts) else None


def is_word_collection(node: ast.AST) -> bool:
    """A collection of two or more lowercase words, at least one an English function word."""
    members = _collection_strings(node)
    if members is None or len(set(members)) < 2 or not all(_WORD.match(m) for m in members):
        return False
    return any(w in FUNCTION_WORDS for m in members for w in [m, *re.split(r"[ '.-]", m)])


def _is_set_algebra(node: ast.AST) -> bool:
    """A `|` / `&` / `-` expression over set names or string sets: a word set built from others."""
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, _SET_OPS):
        return False
    sides = (node.left, node.right)
    return all(isinstance(s, (ast.Name, ast.Attribute, ast.Call, ast.Set, ast.BinOp)) for s in sides) and not any(
        isinstance(s, ast.Constant) for s in sides
    )


def _regex_call(node: ast.AST) -> ast.Call | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in _RE_MODULES
        and node.func.attr in _RE_FUNCS
        and node.args
    ):
        return node
    return None


def _joins_words(node: ast.expr, word_sets: frozenset[str]) -> bool:
    """A `"|".join(...)` inside a pattern over a word set: a word list turned into an alternation."""
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "join"
        and isinstance(n.func.value, ast.Constant)
        and n.func.value.value == "|"
        and any(isinstance(m, ast.Name) and m.id in word_sets for a in n.args for m in ast.walk(a))
        for n in ast.walk(node)
    )


def _word_set_names(rel: str, tree: ast.Module) -> frozenset[str]:
    """Names a module can read as a word set: its own module-level word data and every mapper import."""
    own = {
        name
        for name, node in _top_definitions(tree).items()
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
        and (is_word_collection(node.value) or _is_set_algebra(node.value))
    }
    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and _import_base(rel, node).startswith(f"{PACKAGE}.core.mapper")
        for alias in node.names
    }
    return frozenset(own | imported)


def prose_regex_reason(pattern: str) -> str | None:
    """Why a regex source reads prose: a dash, a clause class, a word alternation or a word tokenizer."""
    if any(d in pattern for d in _DASHES):
        return "cuts at a dash"
    for negated, body in _CHAR_CLASS.findall(pattern):
        if not negated and len(_CLAUSE_MARKS & set(body.replace("\\", ""))) >= 2:
            return "cuts at clause punctuation"
    if _WORD_ALTERNATION.search(pattern):
        return "matches a list of words"
    if _WORD_TOKENIZER.match(pattern.strip()):
        return "splits text into words"
    return None


def _regex_reason(call: ast.Call, constants: dict[str, str], word_sets: frozenset[str]) -> str | None:
    arg = call.args[0]
    if _joins_words(arg, word_sets):
        return "joins a word list into a pattern"
    parts = _literal_parts(arg, constants)
    return prose_regex_reason("".join(parts)) if parts else None


def _markup_literal(text: str) -> bool:
    return "`" in text or ("*" in text and "_" in text)


def _word_shape(value: ast.expr, constants: dict[str, str], word_sets: frozenset[str]) -> str | None:
    """Why a module-level value is word or punctuation data, else None."""
    if is_word_collection(value):
        return "a word list"
    if _is_set_algebra(value):
        return "a word set built from others"
    call = _regex_call(value)
    if call is not None:
        reason = _regex_reason(call, constants, word_sets)
        return f"a regex that {reason}" if reason else None
    parts = _literal_parts(value, constants)
    text = "".join(parts) if parts else ""
    if text and not any(c.isalnum() for c in text) and text.strip():
        return "a punctuation string"
    return None


# ---- T1: copy at the mapper's address ----------------------------------------------------------


def _import_tables(modules: dict[str, ast.Module]) -> dict[str, dict[str, tuple[str, str | None]]]:
    """Per module: local name -> (mapper module, imported name or None for the module itself)."""
    mapper = {_module_name(rel): rel for rel in modules if rel.startswith(MAPPER)}
    tables: dict[str, dict[str, tuple[str, str | None]]] = {}
    for rel, tree in modules.items():
        table: dict[str, tuple[str, str | None]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                base = _import_base(rel, node)
                for alias in node.names:
                    if f"{base}.{alias.name}" in mapper:
                        table[alias.asname or alias.name] = (mapper[f"{base}.{alias.name}"], None)
                    elif base in mapper:
                        table[alias.asname or alias.name] = (mapper[base], alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in mapper:
                        table[alias.asname or alias.name] = (mapper[alias.name], None)
        tables[rel] = table
    return tables


def _references(
    rel: str, node: ast.AST, table: dict[str, tuple[str, str | None]], own: dict[str, ast.stmt]
) -> Iterator[tuple[str, str]]:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            target = table.get(sub.id)
            if target is not None and target[1] is not None:
                yield target[0], target[1]
            elif sub.id in own:
                yield rel, sub.id
        elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
            target = table.get(sub.value.id)
            if target is not None and target[1] is None:
                yield target[0], sub.attr


def map_reach(modules: dict[str, ast.Module]) -> set[tuple[str, str]]:
    """Every `core/mapper/` definition the map entry reaches, following names across modules."""
    tables = _import_tables(modules)
    definitions = {rel: _top_definitions(tree) for rel, tree in modules.items() if rel.startswith(MAPPER)}
    reached: set[tuple[str, str]] = set()
    todo = [(rel, name) for rel in MAP_ENTRY for name in definitions.get(rel, {})]
    while todo:
        key = todo.pop()
        rel, name = key
        if key in reached or name not in definitions.get(rel, {}):
            continue
        reached.add(key)
        todo.extend(_references(rel, definitions[rel][name], tables[rel], definitions[rel]))
    return reached


def mapper_copy_violations(sources: list[Path], root: Path) -> list[Violation]:
    """T1: word or punctuation data in `core/mapper/` the map entry never reaches."""
    modules = _modules(sources, root)
    reached = map_reach(modules)
    out: list[Violation] = []
    for rel, tree in sorted(modules.items()):
        if not rel.startswith(MAPPER) or rel in READER_MODULES:
            continue
        constants = _string_constants(tree)
        word_sets = _word_set_names(rel, tree)
        for name, node in _top_definitions(tree).items():
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if value is None or name.startswith("__") or (rel, name) in reached:
                continue
            shape = _word_shape(value, constants, word_sets)
            if shape is not None:
                site = f"{rel}:{node.lineno}"
                out.append(Violation("T1", site, f"{site} {name} is {shape} the map never reads"))
    return out


# ---- T2: markup handled outside the parser -----------------------------------------------------


def markup_violations(sources: list[Path], root: Path) -> list[Violation]:
    """T2: a markup literal stripped, split or replaced outside the parser modules."""
    out: list[Violation] = []
    for rel, tree in sorted(_modules(sources, root).items()):
        if rel in READER_MODULES:
            continue
        constants = _string_constants(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args):
                continue
            if node.func.attr not in _MARK_CALLS or _regex_call(node) is not None:
                continue
            parts = _literal_parts(node.args[0], constants)
            if parts and _markup_literal("".join(parts)):
                site = f"{rel}:{node.lineno}"
                out.append(
                    Violation("T2", site, f"{site} .{node.func.attr}() handles markdown markup; read the parsed text")
                )
    return out


# ---- T3: re-derivation outside the mapper ------------------------------------------------------


def _literal_slices(tree: ast.Module) -> set[int]:
    """The `Literal[...]` arguments of a module: closed vocabularies the vocabulary floor owns."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and ast.unparse(node.value).split(".")[-1] == "Literal":
            out.update(id(n) for n in ast.walk(node.slice))
    return out


def rederivation_violations(sources: list[Path], root: Path) -> list[Violation]:
    """T3: a word collection, prose regex or prose split in `core/` outside `core/mapper/`."""
    out: list[Violation] = []
    for rel, tree in sorted(_modules(sources, root).items()):
        if not rel.startswith(CORE) or rel.startswith(MAPPER):
            continue
        constants = _string_constants(tree)
        word_sets = _word_set_names(rel, tree)
        skip = _literal_slices(tree)
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            reason = _rederivation(node, constants, word_sets)
            if reason is not None:
                site = f"{rel}:{getattr(node, 'lineno', 0)}"
                found = Violation("T3", site, f"{site} {reason}; read the Atom field the mapper set")
                if found not in out:
                    out.append(found)
    return out


def _rederivation(node: ast.AST, constants: dict[str, str], word_sets: frozenset[str]) -> str | None:
    if is_word_collection(node):
        return "holds a word list"
    call = _regex_call(node)
    if call is not None:
        reason = _regex_reason(call, constants, word_sets)
        return f"compiles a regex that {reason}" if reason else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _SPLIT_CALLS:
        parts = _literal_parts(node.args[0], constants) if node.args else None
        if parts and "".join(parts) in _PROSE_SPLITS:
            return f"splits prose at {''.join(parts)!r}"
    return None


# ---- the floor ---------------------------------------------------------------------------------


def text_reading_violations(sources: list[Path], root: Path) -> list[Violation]:
    """All three rules over `sources`."""
    return [
        *mapper_copy_violations(sources, root),
        *markup_violations(sources, root),
        *rederivation_violations(sources, root),
    ]


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def _format(violations: list[Violation]) -> str:
    lines = [f"{len(violations)} text-reading violation(s):"]
    for rule in ("T1", "T2", "T3"):
        mine = [v for v in violations if v.rule == rule]
        lines.append(f"{rule}: {len(mine)}")
        lines.extend(f"  {v.detail}" for v in mine)
    lines.append("Read the Atom fields (plain_text, named_tokens, lead_in, format, list_depth, heading_context).")
    return "\n".join(lines)


@pytest.mark.architecture
def test_the_mapper_owns_reading_instruction_text() -> None:
    """No unreached word data under the mapper, no markup handled outside the parser, no re-derivation."""
    violations = text_reading_violations(_src_files(), SRC)
    assert not violations, _format(violations)


# ---- planted cases -----------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


_MAPPER_TREE = {
    "core/mapper/pipeline.py": (
        "from reporails_cli.core.mapper.lexicon import read\ndef map_file(t):\n    return read(t)\n"
    ),
    "core/mapper/lexicon.py": (
        "import re\n"
        'USED = frozenset({"when", "unless"})\n'
        "def read(t):\n    return [w for w in t.split() if w in USED]\n"
        'COPIED = frozenset({"such", "like", "including"})\n'
        'BUILT = USED | {"if"}\n'
        'CUT_RE = re.compile(r"\\s[\\u2014\\u2013]\\s")\n'
        'EDGES = ".,;:*_"\n'
        'TYPES = ("agents", "commands")\n'
        "LIMIT = 25\n"
    ),
    "core/mapper/structure.py": 'import re\nURL_RE = re.compile(r"\\s[\\u2014]\\s")\n',
    "core/heal/check.py": "from reporails_cli.core.mapper.lexicon import COPIED\n",
}


@pytest.mark.architecture
def test_t1_fires_on_unreached_word_data_under_the_mapper(tmp_path: Path) -> None:
    """Unreached word lists, set algebra, dash regexes and punctuation strings fire; reached data passes."""
    found = mapper_copy_violations(_plant(tmp_path, _MAPPER_TREE), tmp_path)
    assert {v.site for v in found} == {
        "core/mapper/lexicon.py:5",
        "core/mapper/lexicon.py:6",
        "core/mapper/lexicon.py:7",
        "core/mapper/lexicon.py:8",
    }


@pytest.mark.architecture
def test_t1_follows_reach_across_modules_and_through_a_relocated_cluster(tmp_path: Path) -> None:
    """A helper cluster only heal calls stays unreached even when its members read each other."""
    files = dict(_MAPPER_TREE)
    files["core/mapper/lexicon.py"] += (
        'MARKS = ",;:" + "\\u2014"\ndef split_at_marks(t):\n    return re.split(f"[{MARKS}]", t)\n'
    )
    files["core/heal/check.py"] = "from reporails_cli.core.mapper.lexicon import split_at_marks\n"
    found = mapper_copy_violations(_plant(tmp_path, files), tmp_path)
    assert "core/mapper/lexicon.py:11" in {v.site for v in found}


@pytest.mark.architecture
def test_t2_fires_on_markup_literals_outside_the_parser(tmp_path: Path) -> None:
    """A backtick strip, an emphasis strip and a constant passed by name fire; globs and the parser pass."""
    sources = _plant(
        tmp_path,
        {
            "core/heal/a.py": (
                'TRIM = " .;:*_"\n'
                'def f(t):\n    return t.strip("`"), t.lstrip("*_- "), t.strip(TRIM), t.replace("`", "")\n'
            ),
            "core/discovery/b.py": 'def g(p):\n    return p.lstrip("*/"), p.split("**"), p.replace("_", " ")\n',
            "core/mapper/markers.py": 'def h(t):\n    return t.strip("*_`")\n',
        },
    )
    found = markup_violations(sources, tmp_path)
    assert [v.site for v in found] == ["core/heal/a.py:3"] * 4


@pytest.mark.architecture
def test_t3_fires_on_word_lists_prose_regexes_and_prose_splits(tmp_path: Path) -> None:
    """Word lists, dash and clause regexes, joined word alternations and dash splits fire outside the mapper."""
    sources = _plant(
        tmp_path,
        {
            "core/heal/a.py": (
                "import re\n"
                'LEADS = frozenset({"such", "e.g.", "including"})\n'
                'CUT = re.compile(r"[,;:()\\u2014]")\n'
                'ALT = re.compile(r"\\b(?:for example|such as)\\b")\n'
                'JOINED = re.compile("|".join(sorted(LEADS)))\n'
                'WORDS = re.compile(r"[a-zA-Z0-9]+")\n'
                'def f(t):\n    return t.split(" - "), t.partition(" and ")\n'
            ),
            "core/mapper/lexicon.py": 'OWNED = frozenset({"such", "like"})\n',
        },
    )
    found = rederivation_violations(sources, tmp_path)
    assert [v.site for v in found] == [f"core/heal/a.py:{n}" for n in (2, 3, 4, 5, 6, 8, 8)]


@pytest.mark.architecture
def test_t3_stays_quiet_on_identifier_vocabularies_and_config_splits(tmp_path: Path) -> None:
    """File-type tuples, severity sets, url and id regexes, and `:` / `,` splits of ids pass."""
    sources = _plant(
        tmp_path,
        {
            "core/pipeline/a.py": (
                "import re\n"
                'TYPES = ("skills", "agents", "commands", "hooks")\n'
                'LEVELS = {"error", "warning", "info"}\n'
                'URL = re.compile(r"https?://\\S+")\n'
                'ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")\n'
                'LOOK = re.compile(r"(?<![\\w/.:-])x")\n'
                'def f(rule_id, raw):\n    return rule_id.split(":"), raw.split(","), raw.split(";")\n'
                "from typing import Literal\n"
                'State = Literal["running", "done", "other"]\n'
                'def g(terms):\n    return re.compile("|".join(re.escape(t) for t in terms))\n'
            ),
            "formatters/text/view.py": 'def h(message):\n    return message.split(" \\u2014 ")[0]\n',
        },
    )
    assert rederivation_violations(sources, tmp_path) == []

"""Project-file I/O under `core/` lives only in the named owner modules.

Two rules, pure `ast`, over every `src/reporails_cli/core/**/*.py` outside `core/platform/adapters/`:

- F1 stray file I/O: a content, tree-change or listing call in a module not in `_FILE_OWNERS`.
- F2 stale owner: a `_FILE_OWNERS` module (or a missing file) with no such call.

Detected calls:

- content: builtin `open(...)`, `io.open`, any `<expr>.open(...)`, `.read_text(`, `.read_bytes(`,
  `.write_text(`, `.write_bytes(`, `os.open|read|write|fdopen`;
- tree changes: `.mkdir(`, `.unlink(`, `.rmdir(`, `.touch(`, `.rename(`, `.symlink_to(`,
  `.hardlink_to(`, `.chmod(`, `.replace(` with exactly one positional argument and no keyword
  (`Path.replace`; `str.replace` takes two), `os.replace|rename|remove|unlink|mkdir|makedirs|rmdir|
  link|symlink|chmod|fchmod|utime`, every `shutil.*` call, every `tempfile.*` call;
- listings: `.iterdir(`, `.glob(`, `.rglob(`, `.walk(`, `os.scandir|listdir|walk`, `glob.glob|iglob`.

Known limits, not read: metadata probes (`stat`, `lstat`, `exists`, `is_file`, `is_dir`, `is_symlink`,
`resolve`, `samefile`, `readlink`, `expanduser`, `os.path.*`); I/O through `importlib.resources`; I/O
through `getattr`; a third-party reader handed a path.

No exception list beyond the owner table. The scanners take the source files and their root, so the
planted tests below run the same code on tmp files.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.unit.architecture._module_aliases import module_names

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
CORE = SRC / "core"
ADAPTERS = "platform/adapters/"

# "<path under core/>" -> "<the file family it owns>"
_FILE_OWNERS: dict[str, str] = {
    "discovery/walk.py": "listing the project tree: walks, globs, directory entries",
    "platform/utils/file_read.py": "a file's text, bytes or head",
    "platform/utils/utils.py": "JSON written atomically",
    "heal/file_io.py": "heal's reads and writes of project files",
    "heal/record.py": "heal records",
    "cache/sweep.py": "the global cache folder",
    "mapper/map_cache.py": "map cache files",
    "mapper/full_map_cache.py": "full map cache files",
    "mapper/graph_hash.py": "graph hash files",
    "mapper/serialize.py": "map files",
    "mapper/model_fetch.py": "the model set on disk: staging, swap, locks",
    "mapper/daemon.py": "the daemon's runtime files: pid, lock, socket path",
    "eventbus/store.py": "session logs",
    "eventbus/tail.py": "session logs",
    "eventbus/transcript.py": "transcripts",
    "xray/pages.py": "page records",
    "platform/config/config.py": "user config",
    "platform/config/credentials.py": "credentials",
    "platform/config/claude_settings.py": "Claude Code settings",
    "platform/rules/registry.py": "the rules tree",
    "platform/rules/rules_query.py": "the rules tree",
    "classify/stopwords_sync.py": "rule word-list files",
    "lint/rule_scaffold.py": "new rule folders",
    "lint/harness.py": "the `ails test` fixture workspace",
    "install/self_update.py": "installed distribution metadata",
    "platform/utils/version.py": "installed distribution metadata",
}

_CONTENT_ATTRS = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}
_TREE_ATTRS = {"mkdir", "unlink", "rmdir", "touch", "rename", "symlink_to", "hardlink_to", "chmod"}
_LISTING_ATTRS = {"iterdir", "glob", "rglob", "walk"}
_ATTRS = _CONTENT_ATTRS | _TREE_ATTRS | _LISTING_ATTRS
_OS_CONTENT = {"open", "read", "write", "fdopen"}
_OS_TREE = {
    "replace", "rename", "remove", "unlink", "mkdir", "makedirs", "rmdir", "link", "symlink",
    "chmod", "fchmod", "utime",
}  # fmt: skip
_OS_LISTING = {"scandir", "listdir", "walk"}
_MODULE_FUNCS: dict[str, set[str] | None] = {  # None = every function of the module
    "os": _OS_CONTENT | _OS_TREE | _OS_LISTING,
    "io": {"open"},
    "glob": {"glob", "iglob"},
    "shutil": None,
    "tempfile": None,
}


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _is_io(module: str, name: str) -> bool:
    funcs = _MODULE_FUNCS[module]
    return funcs is None or name in funcs


def _from_imported(tree: ast.Module) -> dict[str, str]:
    """Local name -> `module.func` for each file-I/O function imported by name from a watched module."""
    return {
        alias.asname or alias.name: f"{node.module}.{alias.name}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module in _MODULE_FUNCS and node.level == 0
        for alias in node.names
        if _is_io(node.module, alias.name)
    }


def _attribute_label(func: ast.Attribute, call: ast.Call, aliases: dict[str, set[str]]) -> str | None:
    """The label of a method or module-attribute call that touches the filesystem, else None."""
    base = func.value
    for mod, names in aliases.items():
        if isinstance(base, ast.Name) and base.id in names:
            return f"{mod}.{func.attr}" if _is_io(mod, func.attr) else None
    if func.attr in _ATTRS:
        return f".{func.attr}"
    if func.attr == "replace" and len(call.args) == 1 and not call.keywords:
        return ".replace"
    return None


def file_io_calls(tree: ast.Module) -> list[tuple[int, str]]:
    """Every (line, label) of a detected file-I/O call in a parsed module."""
    aliases = {mod: module_names(tree, mod) for mod in _MODULE_FUNCS}
    from_names = _from_imported(tree)
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        label: str | None = None
        if isinstance(func, ast.Name):
            label = "open" if func.id == "open" else from_names.get(func.id)
        elif isinstance(func, ast.Attribute):
            label = _attribute_label(func, node, aliases)
        if label:
            out.append((node.lineno, label))
    return out


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _scanned(sources: list[Path], root: Path) -> dict[str, list[tuple[int, str]]]:
    return {
        rel: file_io_calls(ast.parse(py.read_text(encoding="utf-8")))
        for py in sources
        if not (rel := _rel(py, root)).startswith(ADAPTERS)
    }


def stray_io_violations(sources: list[Path], root: Path, owners: dict[str, str]) -> list[Violation]:
    """F1: file I/O in a module that is not a named owner."""
    return [
        Violation("F1", f"{rel}:{line} calls {label}")
        for rel, calls in _scanned(sources, root).items()
        if rel not in owners
        for line, label in calls
    ]


def stale_owner_violations(sources: list[Path], root: Path, owners: dict[str, str]) -> list[Violation]:
    """F2: an owner module with no file-I/O call, or no file at all."""
    scanned = _scanned(sources, root)
    return [
        Violation("F2", f"{rel} is a file owner but holds no file I/O call")
        for rel in sorted(owners)
        if not scanned.get(rel)
    ]


def _core_files() -> list[Path]:
    return [p for p in sorted(CORE.rglob("*.py")) if "__pycache__" not in p.parts]


def test_file_io_only_in_the_named_owners() -> None:
    """F1: no content, tree-change or listing call under core/ outside `_FILE_OWNERS`."""
    found = stray_io_violations(_core_files(), CORE, _FILE_OWNERS)
    lines = [f"{len(found)} F1 violation(s): move the call into its file family's owner"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


def test_every_file_owner_still_does_file_io() -> None:
    """F2: every `_FILE_OWNERS` module holds a file-I/O call."""
    found = stale_owner_violations(_core_files(), CORE, _FILE_OWNERS)
    lines = [f"{len(found)} F2 violation(s): drop the stale owner row"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


# ---- planted cases -------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ("def f(p):\n    return p.read_text()\n", "lint/mechanical/checks.py:2 calls .read_text"),
        ("from pathlib import Path\nPath(p).replace(target)\n", "lint/mechanical/checks.py:2 calls .replace"),
        ("import os\nos.scandir('.')\n", "lint/mechanical/checks.py:2 calls os.scandir"),
        ("import tempfile\ntempfile.mkstemp()\n", "lint/mechanical/checks.py:2 calls tempfile.mkstemp"),
        ("import shutil\nshutil.copy(a, b)\n", "lint/mechanical/checks.py:2 calls shutil.copy"),
        ("open(p)\n", "lint/mechanical/checks.py:1 calls open"),
        ("def f(p):\n    return list(p.glob('*'))\n", "lint/mechanical/checks.py:2 calls .glob"),
        ("import io\nio.open(p)\n", "lint/mechanical/checks.py:2 calls io.open"),
        ("import os as o\no.listdir('.')\n", "lint/mechanical/checks.py:2 calls os.listdir"),
        ("from shutil import rmtree\nrmtree(p)\n", "lint/mechanical/checks.py:2 calls shutil.rmtree"),
        ("p.mkdir(parents=True)\n", "lint/mechanical/checks.py:1 calls .mkdir"),
    ],
)
def test_f1_stray_file_io_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of touching the filesystem outside an owner is flagged with its site."""
    sources = _plant(tmp_path, {"lint/mechanical/checks.py": body})
    assert [v.detail for v in stray_io_violations(sources, tmp_path, {})] == [detail]


@pytest.mark.parametrize(
    "body",
    [
        "x = 'a-b'.replace('-', '_')\n",
        "x = s.replace(old, new)\n",
        "ok = p.stat().st_size\n",
        "ok = p.exists() and p.is_file()\n",
        "import os\nx = os.path.join('a', 'b')\n",
    ],
)
def test_f1_metadata_and_str_replace_are_quiet(tmp_path: Path, body: str) -> None:
    """`str.replace`, `.stat()`, `.exists()` and `os.path` are not file I/O for this floor."""
    sources = _plant(tmp_path, {"lint/mechanical/checks.py": body})
    assert stray_io_violations(sources, tmp_path, {}) == []


def test_f1_owner_module_and_adapters_are_quiet(tmp_path: Path) -> None:
    """The same calls pass in an owner module and under `platform/adapters/`."""
    body = "import os\nimport shutil\nopen(p)\nos.scandir('.')\nshutil.copy(a, b)\np.read_text()\n"
    sources = _plant(tmp_path, {"heal/file_io.py": body, "platform/adapters/files.py": body})
    assert stray_io_violations(sources, tmp_path, {"heal/file_io.py": "heal"}) == []


def test_f2_owner_without_calls_is_stale(tmp_path: Path) -> None:
    """An owner module with no file I/O, and an owner with no file, both fail F2."""
    sources = _plant(tmp_path, {"heal/file_io.py": "x = 1\n", "heal/record.py": "p.read_text()\n"})
    owners = {"heal/file_io.py": "a", "heal/record.py": "b", "heal/gone.py": "c"}
    assert [v.detail for v in stale_owner_violations(sources, tmp_path, owners)] == [
        "heal/file_io.py is a file owner but holds no file I/O call",
        "heal/gone.py is a file owner but holds no file I/O call",
    ]

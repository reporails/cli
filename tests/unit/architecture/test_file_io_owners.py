"""Project-file I/O under `core/` lives only in the named owner modules.

Two rules, pure `ast`, over every `src/reporails_cli/core/**/*.py` outside `core/platform/adapters/`:

- F1 stray file I/O: a content, tree-change or listing call in a module not in `_FILE_OWNERS`.
- F2 stale owner: a `_FILE_OWNERS` module (or a missing file) with no such call.

Detected calls:

- content: builtin `open(...)`, `io.open|FileIO|open_code`, any `<expr>.open(...)`, `.read_text(`, `.read_bytes(`,
  `.write_text(`, `.write_bytes(`, `os.open|read|write|fdopen`;
  stdlib readers and writers handed a path: `zipfile.ZipFile|tarfile.open|TarFile|shelve.open|dbm.open|
  sqlite3.connect|gzip.open|GzipFile|bz2.open|BZ2File|lzma.open|LZMAFile|codecs.open|fileinput.input|
  FileInput|mmap.mmap`;
- tree changes: `.mkdir(`, `.unlink(`, `.rmdir(`, `.touch(`, `.rename(`, `.symlink_to(`,
  `.hardlink_to(`, `.chmod(`, `.replace(` with exactly one positional argument and no keyword
  (`Path.replace`; `str.replace` takes two), `os.replace|rename|remove|unlink|mkdir|makedirs|rmdir|
  link|symlink|chmod|fchmod|utime|truncate|removedirs`, every `shutil.*` call, every `tempfile.*` call;
- listings: `.iterdir(`, `.glob(`, `.rglob(`, `.walk(`, `os.scandir|listdir|walk|fwalk`, `glob.glob|iglob`.

References count too, called or not, and are reported as `<label> (reference)`:

- the builtin `open` as a value (`_o = open`, `map(open, ps)`);
- a content, tree-change or listing method, bound or unbound (`map(Path.read_text, ps)`,
  `f = p.read_bytes`); `open`, `glob`, `walk` and `replace` count only unbound on a `Path` class
  (`Path.open|glob|walk|replace`), as other objects carry data attributes of those names;
- any module function above as a value (`map(os.listdir, ps)`, `Z = zipfile.ZipFile`, a name imported
  from the module).

Known limits, not read: metadata probes (`stat`, `lstat`, `exists`, `is_file`, `is_dir`, `is_symlink`,
`resolve`, `samefile`, `readlink`, `expanduser`, `os.path.*`); I/O through `importlib.resources`; I/O
through `getattr` (`getattr(p, "read_text")`) or a name built at run time; a third-party reader handed a
path; a stdlib reader not listed above (`linecache`, `os.copy_file_range`, `os.sendfile`); an `os` call
outside the listed sets (`os.chown`, `os.mkfifo`, `os.renames`, `os.setxattr`, `os.popen`); `Path.lchmod`
(only the listed `Path` methods are read); `vars(builtins)['open']` and `operator.methodcaller('read_text')`
(a method or builtin named by a string is not read); an `open` alias rebound through an assignment the scan cannot
follow (`_o = open` is seen at the assignment, a later `_o(p)` is not a separate hit); a bound
`p.open`, `p.glob` or `p.walk` referenced without a call.

The floor checks which module a call is in, not what the call touches: file I/O inside a module listed in
`_FILE_OWNERS` is not checked against that owner's file family. Owners do I/O by design, and the
`_FILE_OWNERS` value is documentation, not a constraint.

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
_PATH_CLASSES = {"Path", "PurePath", "PosixPath", "WindowsPath"}
# Attribute names that are a filesystem method on any object; `open`, `glob`, `walk` and `replace` are
# also plain data or str attributes, so they count as a reference only on a `Path` class.
_UNAMBIGUOUS_ATTRS = _ATTRS - {"open", "glob", "walk"}
_OS_CONTENT = {"open", "read", "write", "fdopen"}
_OS_TREE = {
    "replace", "rename", "remove", "unlink", "mkdir", "makedirs", "rmdir", "link", "symlink",
    "chmod", "fchmod", "utime", "truncate", "removedirs",
}  # fmt: skip
_OS_LISTING = {"scandir", "listdir", "walk", "fwalk"}
_MODULE_FUNCS: dict[str, set[str] | None] = {  # None = every function of the module
    "os": _OS_CONTENT | _OS_TREE | _OS_LISTING,
    "io": {"open", "FileIO", "open_code"},
    "glob": {"glob", "iglob"},
    # stdlib readers and writers handed a path
    "zipfile": {"ZipFile"},
    "tarfile": {"open", "TarFile"},
    "shelve": {"open"},
    "dbm": {"open"},
    "sqlite3": {"connect"},
    "gzip": {"open", "GzipFile"},
    "bz2": {"open", "BZ2File"},
    "lzma": {"open", "LZMAFile"},
    "codecs": {"open"},
    "fileinput": {"input", "FileInput"},
    "mmap": {"mmap"},
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


def _reference_label(node: ast.AST, aliases: dict[str, set[str]], from_names: dict[str, str]) -> str | None:
    """The label of a file-I/O callable referenced as a value (not called here), else None.

    `map(Path.read_text, ps)`, `_o = open`, `f = p.read_bytes`, `map(os.listdir, ps)`, `Z = zipfile.ZipFile`.
    """
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return "open" if node.id == "open" else from_names.get(node.id)
    if not isinstance(node, ast.Attribute):
        return None
    base = node.value
    for mod, names in aliases.items():
        if isinstance(base, ast.Name) and base.id in names:
            return f"{mod}.{node.attr}" if _is_io(mod, node.attr) else None
    on_path_class = isinstance(base, ast.Name) and base.id in _PATH_CLASSES
    if node.attr in _UNAMBIGUOUS_ATTRS or (on_path_class and (node.attr in _ATTRS or node.attr == "replace")):
        return f".{node.attr}"
    return None


def file_io_calls(tree: ast.Module) -> list[tuple[int, str]]:
    """Every (line, label) of a detected file-I/O call, or reference to a file-I/O callable, in a module."""
    aliases = {mod: module_names(tree, mod) for mod in _MODULE_FUNCS}
    from_names = _from_imported(tree)
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        label: str | None = None
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                label = "open" if func.id == "open" else from_names.get(func.id)
            elif isinstance(func, ast.Attribute):
                label = _attribute_label(func, node, aliases)
        elif id(node) not in called and (ref := _reference_label(node, aliases, from_names)):
            label = f"{ref} (reference)"
        if label:
            out.append((getattr(node, "lineno", 0), label))
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
        ("import os\nos.truncate(p, 0)\n", "lint/mechanical/checks.py:2 calls os.truncate"),
        ("import os\nos.fwalk(p)\n", "lint/mechanical/checks.py:2 calls os.fwalk"),
        ("import os\nos.removedirs(p)\n", "lint/mechanical/checks.py:2 calls os.removedirs"),
        ("import io\nio.FileIO(p)\n", "lint/mechanical/checks.py:2 calls io.FileIO"),
        ("import io\nio.open_code(p)\n", "lint/mechanical/checks.py:2 calls io.open_code"),
        ("from io import FileIO\nFileIO(p)\n", "lint/mechanical/checks.py:2 calls io.FileIO"),
        ("import zipfile\nzipfile.ZipFile(p)\n", "lint/mechanical/checks.py:2 calls zipfile.ZipFile"),
        ("import tarfile\ntarfile.open(p)\n", "lint/mechanical/checks.py:2 calls tarfile.open"),
        ("import shelve\nshelve.open(p)\n", "lint/mechanical/checks.py:2 calls shelve.open"),
        ("import dbm\ndbm.open(p)\n", "lint/mechanical/checks.py:2 calls dbm.open"),
        ("import sqlite3\nsqlite3.connect(p)\n", "lint/mechanical/checks.py:2 calls sqlite3.connect"),
        ("import gzip\ngzip.open(p)\n", "lint/mechanical/checks.py:2 calls gzip.open"),
        ("import bz2\nbz2.open(p)\n", "lint/mechanical/checks.py:2 calls bz2.open"),
        ("import lzma\nlzma.open(p)\n", "lint/mechanical/checks.py:2 calls lzma.open"),
        ("import codecs\ncodecs.open(p)\n", "lint/mechanical/checks.py:2 calls codecs.open"),
        ("import fileinput\nfileinput.input(p)\n", "lint/mechanical/checks.py:2 calls fileinput.input"),
        ("import mmap\nmmap.mmap(fd, 0)\n", "lint/mechanical/checks.py:2 calls mmap.mmap"),
        ("import zipfile as z\nz.ZipFile(p)\n", "lint/mechanical/checks.py:2 calls zipfile.ZipFile"),
        ("from zipfile import ZipFile\nZipFile(p)\n", "lint/mechanical/checks.py:2 calls zipfile.ZipFile"),
        ("from sqlite3 import connect as c\nc(p)\n", "lint/mechanical/checks.py:2 calls sqlite3.connect"),
        (
            "from pathlib import Path\nx = map(Path.read_text, paths)\n",
            "lint/mechanical/checks.py:2 calls .read_text (reference)",
        ),
        ("x = map(Path.iterdir, ps)\n", "lint/mechanical/checks.py:1 calls .iterdir (reference)"),
        ("x = map(Path.unlink, ps)\n", "lint/mechanical/checks.py:1 calls .unlink (reference)"),
        ("x = map(Path.glob, ps)\n", "lint/mechanical/checks.py:1 calls .glob (reference)"),
        ("x = map(Path.replace, ps)\n", "lint/mechanical/checks.py:1 calls .replace (reference)"),
        ("f = p.read_bytes\n", "lint/mechanical/checks.py:1 calls .read_bytes (reference)"),
        ("_o = open\n_o(p)\n", "lint/mechanical/checks.py:1 calls open (reference)"),
        ("x = list(map(open, ps))\n", "lint/mechanical/checks.py:1 calls open (reference)"),
        ("import os\nx = map(os.listdir, ps)\n", "lint/mechanical/checks.py:2 calls os.listdir (reference)"),
        ("from os import listdir\nx = map(listdir, ps)\n", "lint/mechanical/checks.py:2 calls os.listdir (reference)"),
        ("import zipfile\nZ = zipfile.ZipFile\n", "lint/mechanical/checks.py:2 calls zipfile.ZipFile (reference)"),
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
        "import os\nx = os.getcwd()\nos.getenv('A')\n",
        "import io\nb = io.BytesIO()\ns = io.StringIO()\n",
        "import sqlite3\nx = sqlite3.Row\n",
        "import zipfile\nx = zipfile.is_zipfile\nzipfile.BadZipFile\n",
        "def f(open):\n    return 1\nx = 'open'\n",
        "import mmap\nx = mmap.ACCESS_READ\n",
        "x = Path\ny = Path('a') / 'b'\n",
        "x = str.replace\n",
        "class A:\n    glob = 'a'\n    def f(self):\n        return self.glob, self.walk, self.open\n",
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

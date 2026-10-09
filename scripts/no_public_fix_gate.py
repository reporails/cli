#!/usr/bin/env python3
"""Public-rule fix gate: no fix/remediation text in the shipped rule files or public docs.

Fix / remediation guidance is paid content and does not belong on a public surface.
A ``fix:`` frontmatter field or a ``## Fix`` body section in a public ``rule.md`` puts
it into the wheel, the npm tarball, and the public repo.

This gate fails the build if any ``framework/rules/**/rule.md`` carries either.
Run via ``poe arch`` alongside the other structural gates.

A second, content-level check runs when a remedy catalog is available on the machine
running this gate (``AILS_REMEDIES_PATH``, or a local `.env` file): it flags rule
prose, a changelog entry, the README or a docs page sharing a long word-for-word run
with a remedy's action sentence, which the structural check cannot see because the
words never pass through a ``fix:`` key or a ``## Fix`` heading. The check is skipped,
not failed, when no catalog is available.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_ROOT = REPO_ROOT / "framework" / "rules"

# A `fix:` frontmatter key at line start, or a `## Fix` body heading.
_FIX_LINE = re.compile(r"^(fix:|## Fix)", re.MULTILINE)

# Where this gate looks for the remedy catalog, in order: the environment, then an
# `AILS_REMEDIES_PATH=<path>` line in a local `.env` file at the repo root (a relative
# path resolves against the repo root). Neither is required — see the module docstring.
_REMEDIES_PATH_ENV = "AILS_REMEDIES_PATH"
_ENV_FILE = ".env"

# A run this long shared between a rule's prose and a remedy's action sentence
# is not a coincidence of shared vocabulary.
_SHINGLE_SIZE = 8
_WORD_RE = re.compile(r"[a-z0-9']+")
_FENCE_RE = re.compile(r"```.*?```|~~~~.*?~~~~|~~~.*?~~~", re.DOTALL)


def find_public_fix(rules_root: Path) -> list[Path]:
    """Return every ``rule.md`` under ``rules_root`` carrying fix/remediation text."""
    offenders: list[Path] = []
    for rule_md in sorted(rules_root.rglob("rule.md")):
        text = rule_md.read_text(encoding="utf-8")
        if _FIX_LINE.search(text):
            offenders.append(rule_md)
    return offenders


def _env_file_value(key: str) -> str | None:
    """The value of ``key`` in the repo root's ``.env`` (comments and blanks ignored, quotes stripped)."""
    env_file = REPO_ROOT / _ENV_FILE
    if not env_file.is_file():
        return None
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            return value.strip().strip("'\"") or None
    return None


def _resolve_remedies_path() -> Path | None:
    """Return the local remedy catalog path this gate can read, or ``None``."""
    configured = os.environ.get(_REMEDIES_PATH_ENV) or _env_file_value(_REMEDIES_PATH_ENV)
    if configured and (candidate := REPO_ROOT / configured).is_file():
        return candidate.resolve()
    return None


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _shingles(words: list[str]) -> set[str]:
    if len(words) < _SHINGLE_SIZE:
        return set()
    return {" ".join(words[i : i + _SHINGLE_SIZE]) for i in range(len(words) - _SHINGLE_SIZE + 1)}


def _first_sentence(text: str) -> str:
    """The remedy catalog's own convention: the first sentence is the action clause."""
    collapsed = " ".join(text.split())
    m = re.search(r"[.!?](?:\s|$)", collapsed)
    return collapsed[: m.end()].strip() if m else collapsed


def _strip_code_fences(text: str) -> str:
    return _FENCE_RE.sub(" ", text)


def _rule_prose(rule_md_text: str) -> str:
    """The rule's body prose: frontmatter and fenced examples stripped out."""
    body = rule_md_text
    if body.startswith("---"):
        parts = body.split("---", 2)
        if len(parts) == 3:
            body = parts[2]
    return _strip_code_fences(body)


def _iter_remedy_sentences(node: object) -> Iterable[str]:
    """Yield the first sentence of every remedy string leaf in the catalog tree."""
    if isinstance(node, str):
        yield _first_sentence(node)
    elif isinstance(node, dict):
        for value in node.values():
            yield from _iter_remedy_sentences(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_remedy_sentences(item)


def _load_remedy_shingles(remedies_path: Path) -> set[str]:
    """Word-shingles of every remedy action sentence in the local catalog copy."""
    import yaml

    catalog = yaml.safe_load(remedies_path.read_text(encoding="utf-8")) or {}
    shingles: set[str] = set()
    for section in ("levers", "relations", "families"):
        for sentence in _iter_remedy_sentences(catalog.get(section, {})):
            shingles |= _shingles(_words(sentence))
    return shingles


def find_remedy_overlap(rules_root: Path, remedies_path: Path) -> list[Path]:
    """Return every ``rule.md`` whose prose shares an 8-word run with a paid remedy."""
    remedy_shingles = _load_remedy_shingles(remedies_path)
    if not remedy_shingles:
        return []
    offenders: list[Path] = []
    for rule_md in sorted(rules_root.rglob("rule.md")):
        prose_shingles = _shingles(_words(_rule_prose(rule_md.read_text(encoding="utf-8"))))
        if prose_shingles & remedy_shingles:
            offenders.append(rule_md)
    return offenders


def public_doc_files(repo_root: Path) -> list[Path]:
    """The public prose files the content check covers besides the rule pages."""
    files = [repo_root / "UNRELEASED.md", repo_root / "CHANGELOG.md", repo_root / "README.md"]
    files += sorted((repo_root / "docs").glob("*.md"))
    return [f for f in files if f.is_file()]


def find_doc_overlap(files: Iterable[Path], remedies_path: Path) -> list[tuple[Path, list[int]]]:
    """Return each file with the line numbers where an 8-word run matches a paid remedy."""
    remedy_shingles = _load_remedy_shingles(remedies_path)
    if not remedy_shingles:
        return []
    hits: list[tuple[Path, list[int]]] = []
    for path in files:
        words: list[str] = []
        lines: list[int] = []
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            found = _words(line)
            words.extend(found)
            lines.extend([lineno] * len(found))
        matched = sorted(
            {
                lines[i]
                for i in range(len(words) - _SHINGLE_SIZE + 1)
                if " ".join(words[i : i + _SHINGLE_SIZE]) in remedy_shingles
            }
        )
        if matched:
            hits.append((path, matched))
    return hits


def main() -> int:
    offenders = find_public_fix(RULES_ROOT)

    remedies_path = _resolve_remedies_path()
    content_offenders: list[Path] = []
    doc_offenders: list[tuple[Path, list[int]]] = []
    content_checked = False
    if remedies_path is not None:
        try:
            content_offenders = find_remedy_overlap(RULES_ROOT, remedies_path)
            doc_offenders = find_doc_overlap(public_doc_files(REPO_ROOT), remedies_path)
            content_checked = True
        except Exception as exc:  # local, optional input: never block the structural check on it
            print(f"no_public_fix_gate: NOTE — remedy content check errored ({exc}); structural check only.")

    if not offenders and not content_offenders and not doc_offenders:
        print("no_public_fix_gate: OK — no fix:/## Fix in public rule files.")
        if content_checked:
            print("no_public_fix_gate: OK — no rule or public doc restates a paid remedy's action sentence.")
        else:
            print("no_public_fix_gate: NOTE — the remedy catalog is not reachable locally; content check skipped.")
        return 0

    if offenders:
        print("no_public_fix_gate: paid fix content found in public rule files:")
        for path in offenders:
            print(f"  {path.relative_to(REPO_ROOT)}")
    if content_offenders:
        print("no_public_fix_gate: public rule prose restates a paid remedy's action sentence:")
        for path in content_offenders:
            print(f"  {path.relative_to(REPO_ROOT)}")
    if doc_offenders:
        print("no_public_fix_gate: public docs or changelog restate a paid remedy's action sentence:")
        for path, linenos in doc_offenders:
            print(f"  {path.relative_to(REPO_ROOT)}: lines {', '.join(map(str, linenos))}")
    print(
        "\nFAIL: fix/remediation text is paid content and must not live in the open\n"
        "rule files. Delete the `fix:` field and any `## Fix` section, and reword any\n"
        "prose, changelog entries and docs that restate a remedy's action sentence to\n"
        "describe the problem only."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

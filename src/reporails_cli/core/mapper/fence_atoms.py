"""Atoms read from code fences.

A fence stays one neutral block unless it holds charged instruction lines, in which case
each content line becomes an atom of its own.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from typing import Any

from reporails_cli.core.mapper.atom_build import _make_inline_atom
from reporails_cli.core.mapper.charge_floors import _classify_content
from reporails_cli.core.mapper.markers import strip_markdown_inline
from reporails_cli.core.mapper.md_parser import file_lines, md_parser, tok_line
from reporails_cli.core.platform.dto.ruleset import Atom

# The plain form a whole fence kept as one block carries in place of its words:
# `code_block`, or `code_block:<lang>` for a tagged fence.
_FENCE_BLOCK_PLAIN = "code_block"


def is_fence_block(atom: Atom) -> bool:
    """Whether an atom is a whole fence kept as one block, rather than a line read out of a fence."""
    return atom.format == "code_block" and (
        atom.plain_text == _FENCE_BLOCK_PLAIN or atom.plain_text.startswith(f"{_FENCE_BLOCK_PLAIN}:")
    )


def _make_fence_atom(tok: Any, line_offset: int) -> Atom:
    """Create a code block atom from a fence (or indented code_block) token."""
    lang = (tok.info or "").strip().lower()
    return Atom(
        line=tok_line(tok, line_offset),
        text=tok.content[:200],
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="named" if lang else "abstract",
        format="code_block",
        named_tokens=[lang] if lang else [],
        file_path="",
        plain_text=f"{_FENCE_BLOCK_PLAIN}:{lang}" if lang else _FENCE_BLOCK_PLAIN,
    )


# Fence language tags naming text/prose rather than a programming or diagram
# language. A block tagged with one of these is not treated as declared code —
# it falls through to the directive check below.
#
# `markdown`/`md` are deliberately EXCLUDED: an explicit ```markdown / ```md tag
# marks a markup-DEMONSTRATION surface (idiomatic in rule/doc files that show an
# instruction anti-pattern — "Never commit secrets" — inside a fence), not a live
# directive. Scoring it produced a false CONSTRAINT/DIRECTIVE. The dominant real
# case — an UNTAGGED ``` fence carrying a real directive — is preserved via the
# empty tag; a `text`/`txt`-tagged directive is preserved too.
_FENCE_PROSE_TAGS = frozenset({"", "text", "txt", "plaintext", "plain", "prose", "quote", "none"})

# A fence line shorter than this carries no classifiable instruction.
_FENCE_MIN_LINE = 5

# A fenced line that opens with a box-drawing glyph (`├── file.md`, `│`, `└─`) is a
# row of a tree / layout diagram, never an instruction — its bare file name would
# otherwise charge as a verb-first imperative (`test-procedure.md` → "test"). So is a
# flow row whose parts an arrow joins (`Research Analyst -> discovers components`).
_DIAGRAM_LINE_RE = re.compile(r"^[\u2500-\u257f]|\s(?:-+>|=+>|<-+|\u2192|\u27f6)\s")


def _fence_declares_code(lang: str) -> bool:
    """Return True when a fence's language tag names a programming or diagram
    language (`python`, `json`, `mermaid`, …), which the caller keeps as a single
    neutral block rather than reading its lines. A bare or text/prose tag is not
    a code declaration."""
    return bool(lang) and lang not in _FENCE_PROSE_TAGS


# Shell-shaped line openers and operators: an UNTAGGED fence whose lines are mostly
# these is a shell snippet (a `for` loop, a `curl | jq` pipeline), not prose — its
# `echo`/`for` lines must not be read as imperatives. `#` is deliberately absent: a
# markdown heading inside a text fence starts the same way.
_SHELL_LINE_RE = re.compile(
    # Unambiguous shell keywords/commands — safe as bare line openers.
    r"^(?:\$ |\$\(|\$\{|(?:for|while|if|then|else|elif|fi|done|case|esac|echo|export|cd|ls|cat|grep|sed|awk|"
    r"uv|uvx|npm|npx|pnpm|yarn|pip|python3?|git|curl|wget|docker|chmod|mkdir|rm|cp|mv|sudo)\b"
    # Words that are also plain English imperatives (`do not …`, `make sure …`, `set the …`):
    # count as shell ONLY with a shell co-signal — a flag/path/var arg, an assignment, or
    # the bare loop keyword at end of line (`do` / `done`). Otherwise they read as prose.
    r"|(?:do|make|set|source)(?:\s+[-./$~]|\s*$|\s+\w+=))"
    # Operator co-signals for a shell line without a leading command word. ` | ` (a single
    # spaced pipe) is deliberately EXCLUDED: it matches every markdown table row and any prose
    # containing " | ", silencing the whole fence. A real piped command already matches via its
    # leading command word (`cat … | grep …`); `$(`, `${`, `&&`, `||` stay. Trade-off: a fence
    # of custom-script pipes with no recognized command (`render | verify`) now reads as prose
    # and its lines are scored — the safer error than silencing every table/prose directive.
    r"|.*(?:\$\(|\$\{|&&|\|\|)"
)


# A fence whose body carries a markdown heading (`## Audit: {agent}`) is a markdown document
# sample - a report template the agent prints, a file body shown to the reader - the same
# demonstration surface a ```markdown fence is, so its lines are not read as instructions.
def _fence_is_markdown_sample(content: str) -> bool:
    """Return True when a fence's body, read as markdown, carries a `#` heading."""
    return any(tok.type == "heading_open" and tok.markup.startswith("#") for tok in md_parser.parse(content))


def _fence_looks_like_shell(content: str) -> bool:
    """Return True when at least half of a fence's non-empty lines are shell-shaped."""
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    if not lines:
        return False
    return sum(1 for ln in lines if _SHELL_LINE_RE.match(ln)) * 2 >= len(lines)


def _ast_is_trivial(tree: ast.Module) -> bool:
    """Return True when a parsed module is only bare names, constants, or dotted
    attribute references — the shape a one- or two-word text line takes when it
    happens to parse (`Read`, `config.yaml`), which must NOT count as code."""
    if not tree.body:
        return True
    for node in tree.body:
        if not isinstance(node, ast.Expr):
            return False
        if not isinstance(node.value, (ast.Name, ast.Constant, ast.Attribute)):
            return False
    return True


def _fence_parses_as_code(content: str) -> bool:
    """Return True when an untagged block's body is valid JSON, TOML, or
    non-trivial Python — a strict, dependency-free parse. Conservative by
    construction: a bare word or single name parses as Python but is rejected as
    trivial, so a one-line instruction is never mistaken for code."""
    text = content.strip()
    if not text:
        return False
    try:
        json.loads(text)
        return True
    except (ValueError, RecursionError):
        pass
    try:
        tomllib.loads(text)
        return True
    except (tomllib.TOMLDecodeError, ValueError):
        pass
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return not _ast_is_trivial(tree)


def _fence_directive_atoms(
    tok: Any,
    line_offset: int,
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
) -> int | None:
    """Read a fence's lines and, when any line is a charged instruction, append
    one atom per content line (each keeping the `code_block` format) and return
    the advanced `pos_idx`. Return None when no line carries an instruction, so
    the caller falls back to a single neutral block atom."""
    # `tok_line` gives the opening-fence line; content starts on the next line.
    content_line = tok_line(tok, line_offset) + 1
    entries = [
        (idx, stripped)
        for idx, raw in enumerate(file_lines(tok.content))
        if len(stripped := raw.strip()) >= _FENCE_MIN_LINE and not _DIAGRAM_LINE_RE.search(stripped)
    ]
    # Classify each line ONCE (the gate below reuses the same verdict the atom
    # carries — a second classify in atom-build would let the two disagree),
    # off a markdown-STRIPPED plain form. A fenced line's markdown is literal, so
    # `**never**` / `` `never` `` must be stripped before charge classification or
    # the prohibition reads NEUTRAL and is lost on every emphasis-wrapped fenced
    # directive. The raw line stays the atom's display `text`.
    classified = [(idx, line, strip_markdown_inline(line)) for idx, line in entries]
    scored = [(idx, line, plain, _classify_content(line, plain, "code_block")) for idx, line, plain in classified]
    if not scored or not any(verdict[0] != "NEUTRAL" for _idx, _line, _plain, verdict in scored):
        return None
    for idx, line, plain, verdict in scored:
        atoms.append(
            _make_inline_atom(
                line,
                plain,
                "code_block",
                content_line + idx,
                pos_idx=pos_idx,
                current_heading=current_heading,
                precomputed=verdict,
            )
        )
        pos_idx += 1
    return pos_idx


def _process_fence(
    tok: Any,
    line_offset: int,
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
) -> int:
    """Decide how one fence contributes atoms. A block whose tag declares code, or
    whose untagged body parses as code, reads as shell, or is a markdown document
    sample, stays a single neutral block atom. Any other block whose lines carry an
    instruction is read line-by-line so the instruction is scored; a text block with
    no instruction stays neutral."""
    lang = (tok.info or "").strip().lower()
    content = tok.content
    if (
        not _fence_declares_code(lang)
        and not _fence_parses_as_code(content)
        and not _fence_looks_like_shell(content)
        and not _fence_is_markdown_sample(content)
    ):
        advanced = _fence_directive_atoms(tok, line_offset, pos_idx, current_heading, atoms)
        if advanced is not None:
            return advanced
    atoms.append(_make_fence_atom(tok, line_offset))
    return pos_idx

"""Atom construction: token counts, specificity fields and the atom builders.

Builds the `Atom` of one classified line or sentence from its markdown and plain text.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.mapper.charge_floors import _classify_content
from reporails_cli.core.mapper.md_parser import replace_code_spans
from reporails_cli.core.mapper.model_manifest import get_models_path
from reporails_cli.core.platform.dto.ruleset import Atom

logger = logging.getLogger(__name__)


def _strip_backtick_delims(text: str) -> str:
    """`text` with each backtick span's delimiters dropped, its interior words kept.

    A named span's own words are still length, not a single placeholder — `` `pytest
    tests/unit` `` reads several tokens long, not one.
    """
    return replace_code_spans(text, lambda span: span.content)


@lru_cache(maxsize=1)
def _subword_tokenizer() -> Any | None:
    """The bundled subword tokenizer, loaded once, or `None` when it is not on disk yet.

    Token counting needs only the fast tokenizer file, not the ONNX charge graphs, so
    it loads independently of encoder availability — a fresh install or an offline run
    with a partial model cache still counts correctly once the tokenizer itself has
    been fetched. Padding and truncation are disabled so a count is never clipped.
    """
    try:
        import tokenizers  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
    except ImportError:  # a lean install without the tokenizers wheel counts words instead
        return None
    path = get_models_path() / "minilm-l6-v2" / "tokenizer.json"
    if not path.is_file():
        return None
    try:
        tok = tokenizers.Tokenizer.from_file(str(path))
    except Exception as exc:  # pylint: disable=broad-exception-caught  # the tokenizers binding raises a bare Exception for any unreadable file
        logger.warning("Tokenizer file %s could not be loaded: %s", path, exc)
        return None
    tok.no_padding()
    tok.no_truncation()
    return tok


def _count_tokens(text: str) -> int:
    """The subword-token length of `text` — a backticked span counts its own tokens, not one.

    `text` is the instruction without its formatting (the parse's plain text), so an
    emphasis or bold wrap never adds tokens; a fenced line keeps its literal text and
    only loses its backtick delimiters here.

    Falls back to a whitespace word count when the bundled tokenizer is not yet on disk
    (a lean wheel before its first model fetch), so counting a length never fails.
    """
    stripped = _strip_backtick_delims(text)
    tok = _subword_tokenizer()
    if tok is None:
        return len(stripped.split())
    enc = tok.encode(stripped)
    mask = enc.special_tokens_mask
    return len(enc.ids) - sum(mask) if mask else len(enc.ids)


def _specificity_fields(text: str, counted: str | None = None) -> dict[str, Any]:
    """Build specificity-related Atom fields from text.

    The length is counted on `counted` (the text without inline formatting) when given.
    """
    spec, named, unformatted, italic, bold = check_specificity(text)
    return {
        "specificity": spec,
        "named_tokens": named,
        "unformatted_code": unformatted,
        "italic_tokens": italic,
        "bold_tokens": bold,
        "token_count": _count_tokens(text if counted is None else counted),
    }


def _make_inline_atom(
    md_text: str,
    plain_text: str,
    fmt: str,
    line: int,
    *,
    pos_idx: int,
    current_heading: str,
    precomputed: tuple[str, int, str, str, bool] | None = None,
) -> Atom:
    """Create an inline content atom with charge classification.

    `precomputed` supplies an already-computed `_classify_content` verdict so a
    caller that must gate on the charge (the fence cascade) classifies once and
    reuses it here rather than re-running the classifier per atom.
    """
    charge, cv, mod, rule_trace, scope_cond = (
        precomputed
        if precomputed is not None
        else _classify_content(
            md_text,
            plain_text,
            fmt,
        )
    )
    # A fenced line is counted as typed; every other line is counted without its formatting.
    sf = _specificity_fields(md_text, md_text if fmt == "code_block" else plain_text)
    # A fenced line's markdown is LITERAL, not rendered: a `**`/`*`/bare code token
    # is text the author typed INSIDE a code fence, so the rendered-appearance
    # fields (bold / italic / unformatted-code) must stay empty — else a fenced
    # `Never use **mock**` trips bold-on-constraint and italic-constraints as if
    # the `**` were emphasis. The charge/count/specificity
    # signals still carry, so counting fenced directives is unaffected.
    literal_markdown = fmt == "code_block"
    return Atom(
        line=line,
        text=md_text,
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality=mod,
        scope_conditional=scope_cond,
        specificity=sf["specificity"],
        format=fmt,
        named_tokens=sf["named_tokens"],
        italic_tokens=[] if literal_markdown else sf["italic_tokens"],
        bold_tokens=[] if literal_markdown else sf["bold_tokens"],
        unformatted_code=[] if literal_markdown else sf["unformatted_code"],
        position_index=pos_idx,
        token_count=sf["token_count"],
        heading_context=current_heading,
        plain_text=plain_text,
        rule=rule_trace,
        ambiguous=rule_trace.endswith("!amb"),
    )


def _ends_with_colon(plain_text: str) -> bool:
    """True when the text's last character is a colon."""
    return plain_text.rstrip().endswith(":")


def _appearance_fields(text: str, *, literal: bool) -> dict[str, Any]:
    """The specificity and rendered-appearance fields of `text`; a literal (fenced) line renders nothing."""
    spec, named, unformatted, italic, bold = check_specificity(text)
    return {
        "specificity": spec,
        "named_tokens": named,
        "italic_tokens": [] if literal else italic,
        "bold_tokens": [] if literal else bold,
        "unformatted_code": [] if literal else unformatted,
    }


def _atom_from_sentence(
    sent: str,
    atom: Atom,
    verdict: tuple[str, int, str, str, bool],
    *,
    plain_sent: str,
) -> Atom:
    """Create an atom from a sub-sentence of a split atom.

    `verdict` is the sentence's `(charge, charge_value, modality, rule_trace, scope_conditional)`.

    `plain_sent` is the AST-clean form of THIS sentence — pass `sent` itself when
    the caller already fed AST-extracted text. A regex strip of the markers is
    blunt — it deletes every `*` and `_` in the run, not just paired emphasis
    delimiters — so applying it to AST-clean text destroys the identifiers instruction
    files are made of (`fetch_bundled_model`, `*.pem`, `AILS_SERVER_URL`). AST
    extraction drops markers structurally and keeps code-span content verbatim,
    so its output needs no second pass.

    Supplying it also settles the case no in-sentence matcher can: an emphasis
    span wrapping two sentences (`*Do not do X. Do not do Y.*`) leaves each half
    with an unpaired marker, while the AST removed the pair before either half
    existed.

    A part of a fenced line keeps the fenced line's literal markdown: its `**`, `*`
    and bare code tokens are typed text, not emphasis, as in :func:`_make_inline_atom`.
    """
    charge, cv, mod, rule, scope = verdict
    literal_markdown = atom.format == "code_block"
    plain = plain_sent.strip()
    appearance = _appearance_fields(sent, literal=literal_markdown)
    return Atom(
        line=atom.line,
        text=sent,
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality=mod,
        scope_conditional=scope,
        format=atom.format,
        position_index=atom.position_index,
        token_count=_count_tokens(sent if literal_markdown else plain),
        heading_context=atom.heading_context,
        list_depth=atom.list_depth,
        lead_in=atom.lead_in and _ends_with_colon(plain),
        plain_text=plain,
        rule=rule,
        ambiguous=rule.endswith("!amb"),
        imported_from=atom.imported_from,
        imported_line=atom.imported_line,
        **appearance,
    )

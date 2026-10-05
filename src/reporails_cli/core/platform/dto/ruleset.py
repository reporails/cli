"""Pure data shapes for the mapper's wire format — `RulesetMap` and friends.

These dataclasses describe the structure of a mapped instruction ruleset:
atoms with classified charge, file records, and aggregate
statistics. Pure DTOs — no behavior, no I/O. The mapper produces them, the
adapters serialize them, and the lint subsystem inspects them.

Previously lived at `core/mapper/mapper.py`; relocated to `core/platform/dto/`
as part of the hexagonal substrate migration so that adapters and other
consumers do not have to import from the `mapper/` subsystem.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"
# Embedding model id recorded on RulesetMap.embedding_model.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


class InlineToken(BaseModel):
    """A word-level token with format context from AST parsing.

    Carries which words were backticked/bold/italic in an inline segment.
    """

    text: str
    format: str  # "backtick" | "bold" | "italic" | "plain"


class AtomSlots(BaseModel):
    """The 5-tuple slots of an atom (subject/predicate/object/scope + compound),
    populated when available (dev-preview).

    The spans are separated: ``subject`` is the actor (empty for imperatives),
    ``object`` is the value only (no longer fused with subject). ``*_span`` carry
    the corresponding token-offset coordinates when known.
    """

    subject: str = ""
    predicate: str = ""
    object: str = ""  # neutral 5-tuple slot name (subject/predicate/object/scope)
    scope: str = ""
    subject_span: tuple[int, int] | None = None  # [start_tok, end_tok] offsets (None when no span)
    predicate_span: tuple[int, int] | None = None
    object_span: tuple[int, int] | None = None
    scope_span: tuple[int, int] | None = None
    subject_conf: float = 0.0  # per-span confidence for the subject span (0.0 when no span)
    predicate_conf: float = 0.0
    object_conf: float = 0.0
    scope_conf: float = 0.0


# A list item read as the object of the instruction that introduces it: it stays a line of its file
# for the line checks, and takes no place among the file's instructions and context.
LIST_OBJECT_ROLE = "object"


class Atom(BaseModel):
    """A classified content atom from an instruction file."""

    # validate_assignment=False (the default) keeps the mapper's mutate-in-place
    # sites (`atom.charge = …`) raw assignments, behavior-identical to the prior
    # dataclass; atoms are mutated across pipeline stages.
    model_config = ConfigDict(validate_assignment=False)

    line: int
    text: str
    kind: str  # heading, or the default instruction kind
    charge: str  # CONSTRAINT | DIRECTIVE | IMPERATIVE | NEUTRAL | AMBIGUOUS
    charge_value: int  # -1 (constraint), 0 (neutral/ambiguous), +1 (directive/imperative)
    modality: str  # imperative | direct | absolute | hedged | none
    specificity: str  # named | abstract
    scope_conditional: bool = False  # True when conditional frame (if/when/unless) detected
    format: str = "prose"  # prose | heading | list | numbered | table | blockquote | code_block | data_block
    named_tokens: list[str] = Field(default_factory=list)
    italic_tokens: list[str] = Field(default_factory=list)
    bold_tokens: list[str] = Field(default_factory=list)
    caps_tokens: list[str] = []  # all-caps tokens (parallel to named/italic/bold; not yet populated)
    unformatted_code: list[str] = Field(default_factory=list)
    # 0-based document-order index among the file's atoms that hold a place: every non-heading
    # atom and each charged heading; a heading that only titles its section keeps 0, and a list
    # item read as an object (LIST_OBJECT_ROLE) takes -1
    position_index: int = 0
    token_count: int = 0  # approximate word-level token count
    file_path: str = ""  # source file (for cross-file analysis)
    # For an atom whose text an `@path` import brings in: the imported file, relative to the
    # importing file's directory, and the atom's 1-based line there ("" / 0 otherwise). `line`
    # stays the importing file's own line, the `@path` reference.
    imported_from: str = ""
    imported_line: int = 0
    embedding_int8: tuple[int, ...] | None = None  # int8 lexical topic vector (None on headings)
    heading_context: str = ""  # parent heading text
    depth: int | None = None  # heading level 1-6 (set on heading atoms)
    list_depth: int = 0  # how many lists the atom sits in (0 outside a list)
    # True on the last piece of a paragraph line that ends with a colon when a list, a code block or a
    # table follows that paragraph in the file
    lead_in: bool = False
    plain_text: str = ""  # AST-stripped text for NLP/embedding
    rule: str = ""  # which classifier rule fired (p1_negation_phrase, p3c_verb0_use, etc.)
    ambiguous: bool = False  # True when charge depends on verb-noun interpretation
    cell_straddle: bool = False  # coordination flag home (not yet populated)
    embedded_charge_markers: list[str] = Field(default_factory=list)  # opposite-direction markers
    topics: tuple[str, ...] = ()  # noun phrases extracted for topic classification
    role: str = ""  # role within its list or section (LIST_OBJECT_ROLE marks list objects)
    over_merged: bool = False  # granularity audit: clauses span unrelated topics
    min_clause_cosine: float | None = None  # min pairwise clause cosine (None on single-clause atoms)
    abstained: bool = False  # span confidence below the threshold → charge forced NEUTRAL
    stage: str = ""  # provenance of the charge+split decision (e.g. "multislot")
    slots: AtomSlots | None = (
        None  # 5-tuple slots (subject/predicate/object/scope + compound), when available (dev-preview)
    )


class FileRecord(BaseModel):
    """A source file in the ruleset with its loading metadata."""

    path: str
    content_hash: str  # sha256:hex
    loading: str = "session_start"  # session_start | on_demand | on_invocation
    scope: str = "global"  # global | path_scoped | task_scoped
    globs: tuple[str, ...] = ()  # activation patterns (on_demand/on_invocation)
    agent: str = "generic"  # owning agent (claude, codex, copilot, etc.)
    type: str = "generic"  # the matched file type's key in the agent's config (main, rules, skills, …)
    skill: str = ""  # folder of the skill this file belongs to (same path form as `path`); "" in no skill
    description: str = ""  # frontmatter name+description (always in base context)
    description_embedding: tuple[int, ...] | None = None  # int8 quantized embedding


class RulesetSummary(BaseModel):
    """Aggregate statistics for the ruleset."""

    n_atoms: int
    n_charged: int
    n_neutral: int
    n_over_merged: int = 0  # atoms flagged over-merged by the granularity audit


class RulesetMap(BaseModel):
    """Compact map of an instruction ruleset — the wire format."""

    schema_version: str
    embedding_model: str
    generated_at: str  # ISO 8601
    files: tuple[FileRecord, ...]
    atoms: tuple[Atom, ...]
    summary: RulesetSummary = Field(default_factory=lambda: RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0))

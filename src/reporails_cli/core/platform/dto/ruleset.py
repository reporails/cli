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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

SCHEMA_VERSION = "1.0.0"
# Embedding model id recorded on RulesetMap.embedding_model.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# The structural unit an atom was read from.
AtomFormat = Literal["prose", "heading", "list", "numbered", "table", "blockquote", "code_block", "data_block"]
# An item of a bulleted or a numbered list.
LIST_ITEM_FORMATS: frozenset[AtomFormat] = frozenset({"list", "numbered"})
# A paragraph or a list item.
PROSE_OR_LIST_FORMATS: frozenset[AtomFormat] = frozenset({"prose", *LIST_ITEM_FORMATS})
# Text read as sentences: a paragraph, a list item, a quotation and a table row.
RUNNING_TEXT_FORMATS: frozenset[AtomFormat] = frozenset({*PROSE_OR_LIST_FORMATS, "blockquote", "table"})
# A unit whose sentence edges the sentence split decides: a paragraph and a table row; a list item and a
# quotation stay whole.
SENTENCE_SPLIT_FORMATS: frozenset[AtomFormat] = frozenset({"prose", "table"})
# A block that can say what a project is: a paragraph, a quotation or a bulleted list.
DESCRIPTION_FORMATS: frozenset[AtomFormat] = frozenset({"prose", "blockquote", "list"})

# The charge an atom carries.
Charge = Literal["CONSTRAINT", "DIRECTIVE", "IMPERATIVE", "NEUTRAL", "AMBIGUOUS"]
# The charges that carry no instruction.
NO_CHARGE: frozenset[Charge] = frozenset({"NEUTRAL", "AMBIGUOUS"})
# How firmly an atom states its instruction.
Modality = Literal["imperative", "direct", "absolute", "hedged", "none"]
# Whether an atom names a concrete construct.
Specificity = Literal["named", "abstract"]
# How a word of an inline segment is set.
InlineFormat = Literal["backtick", "bold", "italic", "plain"]


# AtomSlots fields carrying the span-coordinate half (token offsets + per-span
# confidence) — the only part of `slots` that is stored. Slot TEXT (the
# subject/predicate/object/scope strings) stays local to the run.
SLOT_SPAN_FIELDS = ("subject_span", "predicate_span", "object_span", "scope_span")
SLOT_COORD_FIELDS = (*SLOT_SPAN_FIELDS, "subject_conf", "predicate_conf", "object_conf", "scope_conf")


def _as_offset(v: JsonValue) -> tuple[int, int] | None:
    """A stored token offset comes back from JSON as a 2-element list; restore the tuple."""
    if v is None:
        return None
    if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], int) and isinstance(v[1], int):
        return (v[0], v[1])
    raise ValueError(f"a stored token offset is a pair of integers, got {v!r}")


def _as_conf(v: JsonValue) -> float:
    """A stored span confidence is a JSON number."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    raise ValueError(f"a stored span confidence is a number, got {v!r}")


class AtomSlots(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
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

    @classmethod
    def from_coords(cls, coords: JsonObject) -> AtomSlots:
        """Rebuild slots from stored span coordinates (JSON hands each offset back as a list)."""
        return cls(
            subject_span=_as_offset(coords.get("subject_span")),
            predicate_span=_as_offset(coords.get("predicate_span")),
            object_span=_as_offset(coords.get("object_span")),
            scope_span=_as_offset(coords.get("scope_span")),
            subject_conf=_as_conf(coords.get("subject_conf", 0.0)),
            predicate_conf=_as_conf(coords.get("predicate_conf", 0.0)),
            object_conf=_as_conf(coords.get("object_conf", 0.0)),
            scope_conf=_as_conf(coords.get("scope_conf", 0.0)),
        )


# A list item read as the object of the instruction that introduces it: it stays a line of its file
# for the line checks, and takes no place among the file's instructions and context.
LIST_OBJECT_ROLE = "object"


class Atom(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """A classified content atom from an instruction file."""

    # validate_assignment=False (the default) keeps the mapper's mutate-in-place
    # sites (`atom.charge = …`) raw assignments, behavior-identical to the prior
    # dataclass; atoms are mutated across pipeline stages.
    model_config = ConfigDict(validate_assignment=False)

    line: int
    text: str
    kind: str  # heading, or the default instruction kind
    charge: Charge
    charge_value: int  # -1 (constraint), 0 (neutral/ambiguous), +1 (directive/imperative)
    modality: Modality
    specificity: Specificity
    scope_conditional: bool = False  # True when conditional frame (if/when/unless) detected
    format: AtomFormat = "prose"
    named_tokens: list[str] = Field(default_factory=list)
    italic_tokens: list[str] = Field(default_factory=list)
    bold_tokens: list[str] = Field(default_factory=list)
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


class FileRecord(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """A source file in the ruleset with its loading metadata."""

    path: str
    content_hash: str  # sha256:hex
    loading: str = "session_start"  # session_start | on_demand | on_invocation
    scope: str = "global"  # global | path_scoped | task_scoped
    globs: tuple[str, ...] = ()  # activation patterns (on_demand/on_invocation)
    agent: str = "generic"  # owning agent (claude, codex, copilot, etc.)
    type: str = "generic"  # the matched file type's key in the agent's config (main, rules, skills, …)
    # when the owning agent loads the file: always | subtree | launch_subtree | file_match | invoked |
    # agent_decides | manual
    activation: str = "always"
    # project files and folders the file's own text points at (backticked paths, links, `@` imports),
    # same path form as `path`, sorted and capped
    reach: tuple[str, ...] = ()
    skill: str = ""  # folder of the skill this file belongs to (same path form as `path`); "" in no skill
    description: str = ""  # frontmatter name+description (always in base context)
    description_embedding: tuple[int, ...] | None = None  # int8 quantized embedding


def int8_bytes(values: tuple[int, ...] | list[int]) -> bytes:
    """Pack an int8 vector as its two's-complement bytes (the encoding the disk cache and the wire share)."""
    return bytes(v & 0xFF for v in values)


def file_record_scalars(record: FileRecord) -> dict[str, str]:
    """The scalar fields of `record` shared by its disk and wire forms, in their fixed key order."""
    return {
        "content_hash": record.content_hash,
        "loading": record.loading,
        "scope": record.scope,
        "agent": record.agent,
        "type": record.type,
    }


class RulesetSummary(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """Aggregate statistics for the ruleset."""

    n_atoms: int
    n_charged: int
    n_neutral: int


class RulesetMap(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """Compact map of an instruction ruleset — the wire format."""

    schema_version: str
    embedding_model: str
    generated_at: str  # ISO 8601
    files: tuple[FileRecord, ...]
    atoms: tuple[Atom, ...]
    summary: RulesetSummary = Field(default_factory=lambda: RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0))

"""Pure data shapes for the mapper's wire format — `RulesetMap` and friends.

These dataclasses describe the structure of a mapped instruction ruleset:
atoms with classified charge, file records, topic clusters, and aggregate
statistics. Pure DTOs — no behavior, no I/O. The mapper produces them, the
adapters serialize them, and the lint subsystem inspects them.

Previously lived at `core/mapper/mapper.py`; relocated to `core/platform/dto/`
as part of the hexagonal substrate migration so that adapters and other
consumers do not have to import from the `mapper/` subsystem.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0.0"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


@dataclass
class InlineToken:
    """A word-level token with format context from AST parsing.

    Used by Phase 3 backtick filter to determine if a ROOT word
    falls inside a backtick span without regex heuristics.
    """

    text: str
    format: str  # "backtick" | "bold" | "italic" | "plain"


@dataclass
class Atom:
    """A classified content atom from an instruction file."""

    line: int
    text: str
    kind: str  # heading | excitation
    charge: str  # CONSTRAINT | DIRECTIVE | IMPERATIVE | NEUTRAL | AMBIGUOUS
    charge_value: int  # q: -1 (constraint), 0 (neutral/ambiguous), +1 (directive/imperative)
    modality: str  # imperative | direct | absolute | hedged | none
    specificity: str  # named | abstract
    scope_conditional: bool = False  # True when conditional frame (if/when/unless) detected
    format: str = "prose"  # prose | heading | list | numbered | table | blockquote | code_block | data_block
    named_tokens: list[str] = field(default_factory=list)
    italic_tokens: list[str] = field(default_factory=list)
    bold_tokens: list[str] = field(default_factory=list)
    unformatted_code: list[str] = field(default_factory=list)
    position_index: int = 0  # 0-based index among non-heading atoms
    token_count: int = 0  # approximate word-level token count
    file_path: str = ""  # source file (for cross-file analysis)
    cluster_id: int = -1  # topic cluster assignment
    embedding_int8: tuple[int, ...] | None = None  # int8 quantized 384-d embedding
    heading_context: str = ""  # parent heading text (for context-aware embedding)
    depth: int | None = None  # heading level 1-6 (set on heading atoms)
    plain_text: str = ""  # AST-stripped text for NLP/embedding
    rule: str = ""  # which classifier rule fired (p1_negation_phrase, p3c_verb0_use, etc.)
    ambiguous: bool = False  # True when charge depends on verb-noun interpretation
    charge_confidence: float = 1.0  # 0.0-1.0 confidence in charge classification
    embedded_charge_markers: list[str] = field(default_factory=list)  # opposite-direction markers
    topics: tuple[str, ...] = ()  # noun phrases from topographer
    role: str = ""  # directive | constraint | anchor | glue


@dataclass
class TopicCluster:
    """A group of atoms on the same topic, from embedding-based clustering."""

    topic_id: int
    atoms: list[Atom]
    charged: list[Atom]
    j: float  # per-topic charge density (structural stat only)
    centroid: tuple[float, ...] = ()  # L2-normalized mean of member embeddings


@dataclass
class FileRecord:
    """A source file in the ruleset with M2 loading metadata."""

    path: str
    content_hash: str  # sha256:hex
    loading: str = "session_start"  # session_start | on_demand | on_invocation
    scope: str = "global"  # global | path_scoped | task_scoped
    globs: tuple[str, ...] = ()  # activation patterns (on_demand/on_invocation)
    agent: str = "generic"  # owning agent (claude, codex, copilot, etc.)
    description: str = ""  # frontmatter name+description (always in base context)
    description_embedding: tuple[int, ...] | None = None  # int8 quantized embedding


@dataclass
class ClusterRecord:
    """A topic cluster with centroid."""

    id: int
    n_atoms: int
    n_charged: int
    n_neutral: int
    centroid: tuple[float, ...] = ()  # 384-d embedding (empty if single-atom cluster)


@dataclass
class RulesetSummary:
    """Aggregate statistics for the ruleset."""

    n_atoms: int
    n_charged: int
    n_neutral: int
    n_topics: int = 0
    n_topics_charged: int = 0


@dataclass
class RulesetMap:
    """Compact map of an instruction ruleset — the wire format."""

    schema_version: str
    embedding_model: str
    generated_at: str  # ISO 8601
    files: tuple[FileRecord, ...]
    atoms: tuple[Atom, ...]
    clusters: tuple[ClusterRecord, ...] = ()
    summary: RulesetSummary = field(default_factory=lambda: RulesetSummary(0, 0, 0))

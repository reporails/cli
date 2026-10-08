"""Server-response and funnel-envelope data shapes.

Frozen dataclasses that define the deserialized diagnostic-response contract
plus the funnel error/envelope shapes. Pure data — no wiring, no I/O. The
adapter deserializes wire JSON into these; formatters and the merger consume
them.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

# The tier vocabulary, in ONE place. Every surface that has to answer "is this
# session entitled?" (the scorecard banner, the funnel CTA, the contact-link
# gate, the sign-in report) reads these sets instead of re-spelling the member
# names.
# A tier string that is in NEITHER set is unknown, not unentitled: the reader
# decides what to do with it (the banner treats it as entitled, the sign-in report
# declines to echo it).
ENTITLED_TIERS = frozenset({"pro", "team"})
UNENTITLED_TIERS = frozenset({"anonymous", "free"})
# The tiers an account can hold: what a sign-in or a key check may name.
ACCOUNT_TIERS = (ENTITLED_TIERS | UNENTITLED_TIERS) - {"anonymous"}


def tier_label(tier: str) -> str:
    """`Pro` for an account tier (Free, Pro, Team); "" for anything else."""
    return tier.capitalize() if tier in ACCOUNT_TIERS else ""


# A short message for the user, as the server sends it. `level` is one of NOTICE_LEVELS;
# `url` is "" when the notice links nowhere.
NOTICE_LEVELS = frozenset({"info", "warn"})


@dataclass(frozen=True)
class Notice:
    """One message for the user: an id (stable across runs), a level, the text, an optional link."""

    id: str
    level: str
    text: str
    url: str = ""


# Failures that clear by themselves: a busy server, a request that took too long, and the
# client's own timeout. They read as "try again", never as a bug.
RETRYABLE_ERRORS = frozenset({"server_busy", "scoring_timeout", "timeout"})
# The 401 tokens: the server did not accept the key it was sent.
AUTH_REJECTED_ERRORS = frozenset({"invalid_api_key", "missing_or_invalid_api_key"})
# Shown instead of "the sign-in ended" when a key made moments ago is rejected.
STILL_REACHING_MESSAGE = "Your sign-in is still reaching the server — try again in a minute."
# Error tokens kept verbatim (with the body's own tier / limits / message). Anything else
# collapses to `unknown_error`, which renders the bug-report link. The 401 tokens are listed
# so an auth rejection renders its sign-in message.
KNOWN_ERRORS = frozenset(
    {
        "rate_limit_exceeded",
        "payload_too_large",
        "atom_cap_exceeded",
        "file_cap_exceeded",
        "scoring_limit_exceeded",
        "project_limit_reached",
        *AUTH_REJECTED_ERRORS,
        *RETRYABLE_ERRORS,
    }
)
# Seconds to wait before retrying when the server names none.
DEFAULT_RETRY_AFTER_S = 10


@dataclass(frozen=True)
class Diagnostic:
    """A single diagnostic from the server."""

    file: str
    line: int
    severity: str  # "error" | "warning" | "info"
    rule: str  # diagnostic rule identifier
    message: str
    fix: str = ""
    impact_tier: str = ""  # server-computed leverage tier; "" when offline/not computed
    pi: int | None = None  # the finding's instruction by its position index in the file; None when line-addressed
    partner_line: int | None = None  # the other side's line of a pairwise finding, when the reply names it
    partner_file: str | None = None  # the file a per-file overlap finding overlaps with, when the reply names it
    overlap_pct: int | None = None  # the share of this file's instructions that overlap, 0-100, when named


@dataclass(frozen=True)
class Hint:
    """An interaction diagnostic hint, shown where line-level detail is not available.

    Surfaces that a problem exists without line-level detail or fix suggestions.
    Severity is preserved so the counts shown stay accurate.
    """

    file: str
    diagnostic_type: str
    count: int
    severity: str = "warning"  # worst severity of the gated diagnostics
    error_count: int = 0  # how many of the gated diagnostics were errors
    warning_count: int = 0  # how many were warnings


@dataclass(frozen=True)
class CrossFileCoordinate:
    """Aggregated cross-file finding (no lines, no detail).

    Shows WHICH files interact and the type/count, but not WHERE or HOW.
    """

    file_1: str
    file_2: str
    finding_type: str  # "repetition" | "overlap" ("conflict" is dropped at merge)
    count: int


@dataclass(frozen=True)
class CrossFileFinding:
    """A cross-file conflict or repetition."""

    file_1: str
    file_2: str
    line_1: int
    line_2: int
    finding_type: str  # "repetition" | "overlap" ("conflict" is dropped at merge)


@dataclass(frozen=True)
class QualityResult:
    """Aggregate quality assessment."""

    # 0-10 whole-project quality score, rendered verbatim. `None` marks an unscored
    # project — matching the per-file `FileAnalysis.display_score` convention.
    display_score: float | None = None


@dataclass(frozen=True)
class FileAnalysis:
    """Per-file server analysis."""

    file: str
    diagnostics: tuple[Diagnostic, ...] = ()
    stats: dict[str, Any] = field(default_factory=dict)
    # 0-10 per-file quality score, rendered verbatim. `None` marks an unscored file
    # (a non-instruction surface or an empty instruction file); rendered as "not scored".
    display_score: float | None = None


@dataclass(frozen=True)
class LocalTier:
    """The grade the reply gives one finding the client reported, at that finding's coordinates."""

    file: str
    rule: str
    line: int
    impact_tier: str


@dataclass(frozen=True)
class RulesetReport:
    """Full server analysis report.

    `local_tiers` holds one row per client-reported finding the reply grades; empty when it grades none.
    """

    per_file: tuple[FileAnalysis, ...] = ()
    local_tiers: tuple[LocalTier, ...] = ()
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult | None = None


@dataclass(frozen=True)
class LocationFinding:
    """One finding of a remediation location: its rule, where it fires, and the operation that fixes it.

    `pi` is the atom's position index when the server addressed it by an instruction,
    `None` for a line-addressed finding. `op` names the operation (`split`, `move`,
    `dedupe`, ...; `""` when the response omits it) and `expect` holds the coordinates that
    operation needs: `{"after": [file, line, pi]}` for a move, `{"keep": [partner_file,
    partner_line]}` for a dedupe or keep-cut, `{}` otherwise.
    `impact_tier` ("gate_mover" | "conditional" | "cosmetic") is this finding's own weight
    — distinct from the location's `importance` — and orders a location's
    findings weakest-first; `""` when the response omits it.

    `members` are the findings this one owns: an instruction owner holds the findings of
    its instruction, a sentence owner holds the instruction-level findings of its line. A
    member is a finding of its own with the same shape and is not also a row of the
    location; `()` for a finding that owns nothing.
    """

    rule: str
    file: str
    line: int
    pi: int | None
    op: str = ""
    expect: dict[str, Any] = field(default_factory=dict)
    impact_tier: str = ""
    members: tuple[LocationFinding, ...] = ()


def walk_findings(findings: Iterable[Any]) -> Iterator[Any]:
    """Every finding of `findings`, each owner followed by its members, depth-first.

    Reads dataclass findings and the dict findings of a serialized workflow alike.
    """
    for f in findings:
        yield f
        members = f.get("members") if isinstance(f, dict) else getattr(f, "members", ())
        yield from walk_findings(members or ())


# A finding's `impact_tier` sort weight — most load-bearing first, so the agent meets the
# finding most likely to gate the file's score before the merely cosmetic ones. A finding with
# no tier sorts last, never first: an unknown weight must not read as the heaviest.
IMPACT_ORDER = {"gate_mover": 0, "conditional": 1, "cosmetic": 2, "": 3}


def subtree_tier_rank(finding: Any) -> int:
    """The `IMPACT_ORDER` weight of the heaviest tier in `finding` and all its members.

    Reads dataclass and dict findings alike.
    """
    tiers = (
        f.get("impact_tier") if isinstance(f, dict) else getattr(f, "impact_tier", "") for f in walk_findings([finding])
    )
    return min(IMPACT_ORDER.get(t or "", 3) for t in tiers)


@dataclass(frozen=True)
class LocationRelation:
    """A cross-file relation (overlap / repetition) folded onto the location's editing side.

    `file` is THIS location's file (the side that edits); `partner_file` / `partner_line`
    name the kept side. `partner_line` is 0 when the partner is unlocated. `op` and `expect`
    read as on `LocationFinding`.
    """

    rule: str
    file: str
    line: int
    partner_file: str
    partner_line: int
    op: str = ""
    expect: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkflowLocation:
    """One remediation location — a harness element, ordered one round per kind, then by importance.

    `files` lists every file of the element that carries a finding or relation. `element`
    is a human label, or a path (absolute, map coordinates) for `main` / `rule` kinds.
    """

    order: int
    element: str
    kind: str  # the files' type as their agent's config names it: "main", "rules", "skills", "agents", …
    loading: str
    files: tuple[str, ...] = ()
    importance: str = ""  # "gate_mover" | "conditional" | "cosmetic"
    findings: tuple[LocationFinding, ...] = ()
    relations: tuple[LocationRelation, ...] = ()


@dataclass(frozen=True)
class ListedFinding:
    """A firing rule that takes no remediation location, with the reason code and how many rows."""

    rule: str
    reason: str
    count: int = 0


@dataclass(frozen=True)
class RemediationWorkflow:
    """The ordered remediation location index for one surface."""

    locations: tuple[WorkflowLocation, ...] = ()
    listed: tuple[ListedFinding, ...] = ()  # every firing rule that takes no location, with its reason
    summary: str = ""


def workflow_summary(locations: Sequence[Any], listed: Sequence[Any]) -> str:
    """The workflow's one-line headline for `locations`: their count, then each kind's count in round order.

    `listed` only chooses the wording when no location is left.
    """
    if not locations:
        if listed:
            return "Nothing to rewrite — every finding is listed with the reason it takes none."
        return "No remediation needed — the surface carries no findings."
    kinds = [loc.kind for loc in locations]
    parts = [f"{kinds.count(k)} {k}" for k in dict.fromkeys(kinds)]
    n = len(locations)
    return f"{n} location{'' if n == 1 else 's'} to rewrite, by kind: {', '.join(parts)}."


@dataclass(frozen=True)
class LintResult:
    """Result from lint() — wraps report + hints for tier gating."""

    report: RulesetReport
    hints: tuple[Hint, ...] = ()
    cross_file_coordinates: tuple[CrossFileCoordinate, ...] = ()
    # Empty means "the response named no tier" — never assume a tier the server
    # did not send; readers fall back on what the payload itself carries.
    tier: str = ""
    # The composable remediation HOW; `None` when the response carries none.
    workflow: RemediationWorkflow | None = None


@dataclass(frozen=True)
class FunnelError:
    """Funnel error shape for server 4xx bodies, local preflight failures, and transport failures.

    ``status`` carries the wire HTTP status when one exists (a parsed 4xx/5xx body); it is
    ``None`` for a local preflight rejection (no round-trip happened) and for the transport-level
    tokens (``timeout``, ``network_error``, ``malformed_response``) where no status was received.
    """

    error: str
    tier: str = ""
    limit: int = 0
    size: int = 0
    files: int = 0
    reset_in: int = 0
    upgrade_url: str = ""
    support_url: str = ""
    message: str = ""
    status: int | None = None

    @property
    def retryable(self) -> bool:
        """True for a failure that clears on its own, so the user is told to try again.

        A key rejected moments after sign-in (the still-reaching message) clears the same way.
        """
        return self.error in RETRYABLE_ERRORS or self.still_reaching

    @property
    def still_reaching(self) -> bool:
        """True when a just-made key was rejected and the sign-in has not reached the server yet."""
        return self.error in AUTH_REJECTED_ERRORS and self.message == STILL_REACHING_MESSAGE

    @property
    def reset_phrase(self) -> str:
        """Render reset_in as a CTA fragment: 'Try again in ~N min. ' or ''."""
        if self.reset_in <= 0:
            return ""
        minutes = (self.reset_in + 59) // 60
        label = "<1 min" if minutes <= 1 else f"~{minutes} min"
        return f"Try again in {label}. "


@dataclass(frozen=True)
class LintResponse:
    """Envelope returned by AilsClient.lint()."""

    result: Any = None
    funnel_error: FunnelError | None = None
    # The messages the server sent with this reply, success or error; empty when it sent none.
    notices: tuple[Notice, ...] = ()

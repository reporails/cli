"""API client for reporails diagnostic server.

Sends text-stripped RulesetMap to the diagnostic API (default: api.reporails.com)
and deserializes the response. AILS_SERVER_URL overrides the default endpoint.

Response dataclasses define the wire format — shared contract between CLI and API.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from reporails_cli.core.funnel import (
    LintResponse,
    parse_error_body,
    preflight_oversized,
)
from reporails_cli.core.platform.contract.errors import (
    ConfigUnreadableError,
    CredentialsUnreadableError,
    PlatformError,
)
from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)


def _user_agent() -> str:
    """Return `reporails-cli/<version>` for outgoing diagnostic requests.

    Sending a distinct UA lets the server (and any CDN/WAF in front of it)
    identify legitimate CLI traffic. The default `python-httpx/*` UA is a
    common bot-fight trigger.
    """
    try:
        from importlib.metadata import version

        return f"reporails-cli/{version('reporails-cli')}"
    except Exception:  # importlib.metadata.PackageNotFoundError + defensive
        return "reporails-cli/unknown"


# ──────────────────────────────────────────────────────────────────
# RESPONSE DATACLASSES
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Diagnostic:
    """A single diagnostic from the server."""

    file: str
    line: int
    severity: str  # "error" | "warning" | "info"
    rule: str  # diagnostic rule identifier
    message: str
    fix: str = ""
    line_2: int = 0  # secondary line (conflict pairs)
    impact_tier: str = ""  # server-computed leverage tier; "" when offline/not computed


@dataclass(frozen=True)
class Hint:
    """An interaction diagnostic hint (free tier).

    Surfaces that a problem exists without line-level detail or fix suggestions.
    The detection is the gift; the fix is the product.
    Severity is preserved so the free tier can show honest error/warning counts.
    """

    file: str
    diagnostic_type: str
    count: int
    summary: str
    severity: str = "warning"  # worst severity of the gated diagnostics
    error_count: int = 0  # how many of the gated diagnostics were errors
    warning_count: int = 0  # how many were warnings


@dataclass(frozen=True)
class CrossFileCoordinate:
    """Aggregated cross-file finding for free tier (no lines, no detail).

    Shows WHICH files interact and the type/count, but not WHERE or HOW.
    The detection is the gift; the fix is the product.
    """

    file_1: str
    file_2: str
    finding_type: str  # "conflict" | "repetition"
    count: int


@dataclass(frozen=True)
class CrossFileFinding:
    """A cross-file conflict or repetition."""

    file_1: str
    file_2: str
    line_1: int
    line_2: int
    charge_1: int
    charge_2: int
    finding_type: str  # "conflict" | "repetition"
    topicality: str = ""  # "near" | "moderate" | "far"; "" when offline/not computed


@dataclass(frozen=True)
class TargetScore:
    """Per-instruction compliance breakdown (Pro tier)."""

    line: int
    file_path: str
    compliance_band: str  # "HIGH" | "MODERATE" | "LOW"
    impact_rank: int
    capacity: str = ""  # "low" | "moderate" | "high"; "" when offline/not computed
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True)
class ContextResult:
    """Results for a loading context."""

    context_name: str
    files: tuple[str, ...] = ()
    compliance_band: str = ""
    n_charged: int = 0
    n_atoms: int = 0
    per_target: tuple[TargetScore, ...] = ()


@dataclass(frozen=True)
class QualityResult:
    """Aggregate quality assessment."""

    contexts: tuple[ContextResult, ...] = ()
    compliance_band: str = ""  # aggregate
    # Server-computed 0-10 whole-project quality score. The CLI renders it verbatim —
    # it computes no score of its own.
    display_score: float = 0.0
    weakest_context: str | None = None
    strongest_context: str | None = None


@dataclass(frozen=True)
class FileAnalysis:
    """Per-file server analysis."""

    file: str
    diagnostics: tuple[Diagnostic, ...] = ()
    compliance_band: str = ""
    stats: dict[str, Any] = field(default_factory=dict)
    # Server-computed 0-10 per-file quality score. Rendered verbatim; mean-aggregated
    # for surface scores. `None` marks an unscored file (no charged atoms — a
    # non-instruction surface or an empty instruction file); rendered as "not scored"
    # and excluded from surface aggregation.
    display_score: float | None = None


@dataclass(frozen=True)
class RulesetReport:
    """Full server analysis report."""

    per_file: tuple[FileAnalysis, ...] = ()
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult = field(default_factory=QualityResult)
    stats: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class LintResult:
    """Result from lint() — wraps report + hints for tier gating."""

    report: RulesetReport
    hints: tuple[Hint, ...] = ()
    cross_file_coordinates: tuple[CrossFileCoordinate, ...] = ()
    tier: str = "free"


# ──────────────────────────────────────────────────────────────────
# CLIENT
# ──────────────────────────────────────────────────────────────────


def _tier_from_config() -> str:
    """Read tier from global config (~/.reporails/config.yml).

    Returns "" only for genuine absence (no config / no tier). Raises
    ConfigUnreadableError when the config exists but cannot be read.
    """
    try:
        from reporails_cli.core.platform.config.config import get_global_config
    except ImportError:
        logger.debug("Config module unavailable — defaulting tier")
        return ""
    try:
        return get_global_config().tier
    except (OSError, AttributeError) as exc:
        raise ConfigUnreadableError(f"Could not read tier from config: {exc}") from exc


def _api_key_from_credentials() -> str:
    """Read API key from ~/.reporails/credentials.yml (set by `ails auth login`).

    Returns "" only for genuine absence (no file / no key). Raises
    CredentialsUnreadableError when the file exists but cannot be read or parsed.
    """
    from pathlib import Path

    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed — cannot read credentials")
        return ""

    path = Path.home() / ".reporails" / "credentials.yml"
    if not path.exists():
        return ""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CredentialsUnreadableError(f"Could not read credentials file: {exc}") from exc
    return data.get("api_key", "") if isinstance(data, dict) else ""


def _degrade_on_fault(reader: Callable[[], str], unit: str) -> str:
    """Run a credentials/config read; on PlatformError drop the unit with a visible WARNING.

    The legitimate crash-firewall: a corrupt file surfaces as a WARNING and the
    session continues anonymous, rather than crashing or being debug-buried.
    """
    try:
        return reader()
    except PlatformError as exc:
        logger.warning("Dropping %s and continuing anonymous: %s", unit, exc)
        return ""


def has_api_key() -> bool:
    """True when an API key is available (env override or stored credentials).

    Client-side affordance gate: distinguishes an authenticated user from an
    anonymous one without consulting the server. The server remains the tier
    authority; this only gates which local affordances are offered.
    """
    if os.environ.get("AILS_API_KEY"):
        return True
    return bool(_degrade_on_fault(_api_key_from_credentials, "API key"))


class AilsClient:
    """Diagnostic API client — HTTP to diagnostic API, local fallback.

    Sends a text-stripped RulesetMap to the diagnostic API (default:
    api.reporails.com) via POST /diagnose. AILS_SERVER_URL overrides
    the endpoint. Returns None when the server is unreachable.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        tier: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("AILS_SERVER_URL", "https://api.reporails.com")
        self.api_key = (
            api_key or os.environ.get("AILS_API_KEY") or _degrade_on_fault(_api_key_from_credentials, "API key")
        )
        self.tier = tier or os.environ.get("AILS_TIER") or _degrade_on_fault(_tier_from_config, "tier") or "free"
        self.timeout = timeout

    def lint(
        self,
        ruleset_map: RulesetMap,
        local_findings: dict[str, int] | None = None,
        structural_required: int = 0,
    ) -> LintResponse:
        """Run diagnostics on a ruleset map via the API.

        `local_findings` is a `{path: structural-error count}` map for rules that
        run client-side (structural/presence checks), and `structural_required` is
        the count of structural rule classes the project is subject to. Both ride the
        request so the server can fold the client-measured delivery factor into each
        file's score. Returns LintResponse — `.result` on 2xx, `.funnel_error` on a
        tier-aware 4xx or local preflight rejection, both None on network failure.
        """
        if not self.base_url:
            logger.debug("No server URL configured — diagnostics unavailable offline")
            return LintResponse()
        return self._lint_remote(ruleset_map, local_findings or {}, structural_required)

    def _lint_remote(
        self, ruleset_map: RulesetMap, local_findings: dict[str, int], structural_required: int
    ) -> LintResponse:
        """POST the projected RulesetMap to the diagnostic backend."""
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed — cannot use remote diagnostics")
            return LintResponse()

        from reporails_cli.core.platform.adapters.payload import encode_msgpack, project_payload

        payload = project_payload(ruleset_map)
        if local_findings:
            payload["local_findings"] = local_findings
        if structural_required:
            payload["structural_required"] = structural_required
        if not payload.get("files"):
            logger.warning("No instruction files in payload — skipping remote diagnostics")
            return LintResponse()
        cap_error = preflight_oversized(payload, has_api_key=bool(self.api_key))
        if cap_error is not None:
            logger.warning("Preflight rejected payload: %s (%d/%d)", cap_error.error, cap_error.size, cap_error.limit)
            return LintResponse(funnel_error=cap_error)
        body = encode_msgpack(payload)
        from reporails_cli.core.funnel import preflight_byte_size

        byte_error = preflight_byte_size(len(body), has_api_key=bool(self.api_key))
        if byte_error is not None:
            logger.warning("Preflight rejected payload bytes: %d > %d", byte_error.size, byte_error.limit)
            return LintResponse(funnel_error=byte_error)
        return self._post_payload(httpx, body)

    def _post_payload(self, httpx: Any, body: bytes) -> LintResponse:
        """Execute the HTTP round-trip; isolated so _lint_remote stays within return-count budget."""
        dev_mode = os.environ.get("AILS_DEV_MODE", "").lower() in ("true", "1")
        ua = _user_agent()
        if dev_mode:
            url = f"{self.base_url.rstrip('/')}/diagnose"
            headers: dict[str, str] = {
                "X-Tier": self.tier,
                "Content-Type": "application/msgpack",
                "User-Agent": ua,
            }
        else:
            url = f"{self.base_url.rstrip('/')}/v1/diagnose"
            headers = {"Content-Type": "application/msgpack", "User-Agent": ua}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = httpx.post(url, content=body, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return LintResponse(result=_deserialize_lint_result(resp.json()))
        except httpx.TimeoutException:
            logger.warning("Remote diagnostic request timed out after %.1fs", self.timeout)
            return LintResponse()
        except httpx.HTTPStatusError as exc:
            funnel_err = parse_error_body(exc.response.status_code, exc.response.text)
            if funnel_err is not None:
                logger.debug(
                    "Server returned %d %s for tier=%s", exc.response.status_code, funnel_err.error, funnel_err.tier
                )
                return LintResponse(funnel_error=funnel_err)
            logger.warning("Remote diagnostic returned HTTP %d (no parseable body)", exc.response.status_code)
            return LintResponse()
        except httpx.HTTPError as exc:
            logger.warning("Remote diagnostic network error: %s", exc)
            return LintResponse()
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            logger.warning("Remote diagnostic response malformed: %s", exc)
            return LintResponse()


# ──────────────────────────────────────────────────────────────────
# WIRE FORMAT — serialization for API transport (v2, obfuscated)
# ──────────────────────────────────────────────────────────────────

# Encoding tables — map semantic names to wire-format short codes.
# These exist ONLY in source code; they never appear in output.
_CHARGE_ENC = {"CONSTRAINT": 0, "DIRECTIVE": 1, "IMPERATIVE": 2, "NEUTRAL": 3, "AMBIGUOUS": 4}
_MODALITY_ENC = {"imperative": 0, "direct": 1, "absolute": 2, "hedged": 3, "none": 4}
_SPECIFICITY_ENC = {"named": 0, "abstract": 1}
_FORMAT_ENC = {
    "prose": 0,
    "heading": 1,
    "list": 2,
    "numbered": 3,
    "table": 4,
    "blockquote": 5,
    "code_block": 6,
    "data_block": 7,
}
_KIND_ENC = {"heading": 0, "excitation": 1}
_STYLE_ENC = {"backtick": 0, "italic": 1, "bold": 2, "none": 3}


def _serialize_atom(a: Any, file_idx: dict[str, int]) -> dict[str, Any]:
    """Serialize a single atom to v2 wire format."""
    d: dict[str, Any] = {
        "line": a.line,
        "t": _KIND_ENC.get(a.kind, 1),
        "c": _CHARGE_ENC.get(a.charge, 3),
        "cv": a.charge_value,
        "m": _MODALITY_ENC.get(a.modality, 4),
        "s": _SPECIFICITY_ENC.get(a.specificity, 1),
        "sc": a.scope_conditional,
        "f": _FORMAT_ENC.get(a.format, 0),
        "pi": a.position_index,
        "tc": a.token_count,
        "fi": file_idx.get(a.file_path, -1),
        "k": a.cluster_id,
    }
    il = [
        *[{"term": tok, "s": 0} for tok in a.named_tokens],
        *[{"term": tok, "s": 1} for tok in a.italic_tokens],
        *[{"term": tok, "s": 2} for tok in a.bold_tokens],
        *[{"term": tok, "s": 3} for tok in a.unformatted_code],
    ]
    if il:
        d["il"] = il
    if a.embedding_int8 is not None:
        raw = bytes(v & 0xFF for v in a.embedding_int8)
        d["e"] = base64.b64encode(raw).decode("ascii")
    if a.heading_context:
        d["hc"] = a.heading_context
    if a.depth is not None:
        d["d"] = a.depth
    if a.ambiguous:
        d["a"] = True
    if a.embedded_charge_markers:
        d["ecm"] = list(a.embedded_charge_markers)
    return d


def _serialize_files(ruleset_map: RulesetMap) -> list[dict[str, Any]]:
    """Serialize file entries to v2 wire format."""
    import numpy as np

    files_out = []
    for f in ruleset_map.files:
        fd: dict[str, Any] = {
            "path": f.path,
            "content_hash": f.content_hash,
            "loading": f.loading,
            "scope": f.scope,
            "agent": f.agent,
        }
        if f.globs:
            fd["globs"] = list(f.globs)
        if f.description:
            fd["description"] = f.description
        if f.description_embedding:
            raw = np.asarray(f.description_embedding, dtype=np.int8).tobytes()
            fd["description_embedding_b64"] = base64.b64encode(raw).decode("ascii")
        files_out.append(fd)
    return files_out


def _serialize_clusters(ruleset_map: RulesetMap) -> list[dict[str, Any]]:
    """Serialize cluster entries to v2 wire format."""
    import numpy as np

    clusters_out = []
    for c in ruleset_map.clusters:
        cd: dict[str, Any] = {
            "id": c.id,
            "n_atoms": c.n_atoms,
            "n_charged": c.n_charged,
            "n_neutral": c.n_neutral,
        }
        if c.centroid:
            raw = np.asarray(c.centroid, dtype=np.float32).tobytes()
            cd["centroid_b64"] = base64.b64encode(raw).decode("ascii")
        clusters_out.append(cd)
    return clusters_out


def _strip_and_serialize(ruleset_map: RulesetMap) -> dict[str, Any]:
    """Serialize RulesetMap to v2 wire format (obfuscated field names).

    Strips text, plain_text, rule, role, topics from atoms.
    Replaces semantic field names with short codes and enum strings with integers.
    Instruction content never leaves the client.
    """
    file_idx = {f.path: i for i, f in enumerate(ruleset_map.files)}

    return {
        "schema_version": "2",
        "embedding_model": ruleset_map.embedding_model,
        "generated_at": ruleset_map.generated_at,
        "files": _serialize_files(ruleset_map),
        "atoms": [_serialize_atom(a, file_idx) for a in ruleset_map.atoms],
        "clusters": _serialize_clusters(ruleset_map),
        "summary": {
            "n_atoms": ruleset_map.summary.n_atoms,
            "n_charged": ruleset_map.summary.n_charged,
            "n_neutral": ruleset_map.summary.n_neutral,
            "n_topics": ruleset_map.summary.n_topics,
            "n_topics_charged": ruleset_map.summary.n_topics_charged,
        },
    }


def _deserialize_per_file(report_data: dict[str, Any]) -> tuple[FileAnalysis, ...]:
    """Deserialize the per_file section of the API response."""
    items: list[FileAnalysis] = []
    for fa in report_data.get("per_file", []):
        fa_file = fa.get("file")
        if fa_file is None:
            logger.warning("Skipping per_file entry with missing 'file' key")
            continue
        diagnostics: list[Diagnostic] = []
        for d in fa.get("diagnostics", []):
            d_line = d.get("line")
            d_severity = d.get("severity")
            d_rule = d.get("rule")
            d_message = d.get("message")
            if d_line is None or d_severity is None or d_rule is None or d_message is None:
                logger.warning(
                    "Skipping diagnostic with missing required field in file %s: %s",
                    fa_file,
                    d,
                )
                continue
            diagnostics.append(
                Diagnostic(
                    file=d.get("file", fa_file),
                    line=d_line,
                    severity=d_severity,
                    rule=d_rule,
                    message=d_message,
                    fix=d.get("fix", ""),
                    line_2=d.get("line_2", 0),
                    impact_tier=d.get("impact_tier", ""),
                )
            )
        items.append(
            FileAnalysis(
                file=fa_file,
                diagnostics=tuple(diagnostics),
                compliance_band=fa.get("compliance_band", ""),
                stats=fa.get("stats", {}),
                display_score=fa.get("display_score"),
            )
        )
    return tuple(items)


def _deserialize_cross_file(report_data: dict[str, Any]) -> tuple[CrossFileFinding, ...]:
    """Deserialize the cross_file section of the API response."""
    items: list[CrossFileFinding] = []
    _required_keys = ("file_1", "file_2", "line_1", "line_2", "charge_1", "charge_2", "finding_type")
    for cf in report_data.get("cross_file", []):
        vals = {k: cf.get(k) for k in _required_keys}
        if any(v is None for v in vals.values()):
            logger.warning("Skipping cross_file entry with missing required field: %s", cf)
            continue
        items.append(
            CrossFileFinding(
                file_1=vals["file_1"],
                file_2=vals["file_2"],
                line_1=vals["line_1"],
                line_2=vals["line_2"],
                charge_1=vals["charge_1"],
                charge_2=vals["charge_2"],
                finding_type=vals["finding_type"],
                topicality=cf.get("topicality", ""),
            )
        )
    return tuple(items)


def _deserialize_quality(report_data: dict[str, Any]) -> QualityResult:
    """Deserialize the quality section of the API response."""
    q_data = report_data.get("quality", {})
    context_items: list[ContextResult] = []
    for ctx in q_data.get("contexts", []):
        ctx_name = ctx.get("context_name")
        if ctx_name is None:
            logger.warning("Skipping context entry with missing 'context_name'")
            continue
        target_items: list[TargetScore] = []
        for ts in ctx.get("per_target", []):
            ts_line = ts.get("line")
            ts_path = ts.get("file_path")
            ts_band = ts.get("compliance_band")
            ts_rank = ts.get("impact_rank")
            if any(v is None for v in (ts_line, ts_path, ts_band, ts_rank)):
                logger.warning(
                    "Skipping per_target entry with missing required field in context %s: %s",
                    ctx_name,
                    ts,
                )
                continue
            target_items.append(
                TargetScore(
                    line=ts_line,
                    file_path=ts_path,
                    compliance_band=ts_band,
                    impact_rank=ts_rank,
                    capacity=ts.get("capacity", ""),
                )
            )
        context_items.append(
            ContextResult(
                context_name=ctx_name,
                files=tuple(ctx.get("files", [])),
                compliance_band=ctx.get("compliance_band", ""),
                n_charged=ctx.get("n_charged", 0),
                n_atoms=ctx.get("n_atoms", 0),
                per_target=tuple(target_items),
            )
        )
    return QualityResult(
        contexts=tuple(context_items),
        compliance_band=q_data.get("compliance_band", ""),
        display_score=q_data.get("display_score", 0.0),
        weakest_context=q_data.get("weakest_context"),
        strongest_context=q_data.get("strongest_context"),
    )


def _deserialize_hints(data: dict[str, Any]) -> tuple[Hint, ...]:
    """Deserialize the hints section of the API response."""
    items: list[Hint] = []
    for h in data.get("hints", []):
        h_file = h.get("file")
        h_type = h.get("diagnostic_type")
        h_count = h.get("count")
        h_summary = h.get("summary")
        if any(v is None for v in (h_file, h_type, h_count, h_summary)):
            logger.warning("Skipping hint entry with missing required field: %s", h)
            continue
        items.append(
            Hint(
                file=h_file,
                diagnostic_type=h_type,
                count=h_count,
                summary=h_summary,
                severity=h.get("severity", "warning"),
                error_count=h.get("error_count", 0),
                warning_count=h.get("warning_count", 0),
            )
        )
    return tuple(items)


def _deserialize_cross_file_coordinates(data: dict[str, Any]) -> tuple[CrossFileCoordinate, ...]:
    """Deserialize the cross_file_coordinates section of the API response."""
    items: list[CrossFileCoordinate] = []
    for c in data.get("cross_file_coordinates", []):
        f1 = c.get("file_1")
        f2 = c.get("file_2")
        ft = c.get("finding_type")
        cnt = c.get("count")
        if any(v is None for v in (f1, f2, ft, cnt)):
            logger.warning("Skipping cross_file_coordinate with missing field: %s", c)
            continue
        items.append(CrossFileCoordinate(file_1=f1, file_2=f2, finding_type=ft, count=cnt))
    return tuple(items)


def _deserialize_lint_result(data: dict[str, Any]) -> LintResult:
    """Deserialize API JSON response to LintResult."""
    report_data = data.get("report")
    if not isinstance(report_data, dict):
        logger.warning("API response missing 'report' key or not a dict")
        # Forward the server tier even on a malformed report — dropping it here silently
        # relabels a pro/anonymous session as the default 'free' downstream.
        return LintResult(report=RulesetReport(), tier=data.get("tier", "free"))

    report = RulesetReport(
        per_file=_deserialize_per_file(report_data),
        cross_file=_deserialize_cross_file(report_data),
        quality=_deserialize_quality(report_data),
        stats=report_data.get("stats", {}),
    )

    return LintResult(
        report=report,
        hints=_deserialize_hints(data),
        cross_file_coordinates=_deserialize_cross_file_coordinates(data),
        tier=data.get("tier", "free"),
    )

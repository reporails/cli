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
from dataclasses import dataclass, field
from typing import Any

from reporails_cli.core.mapper.mapper import RulesetMap

logger = logging.getLogger(__name__)


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
    distance: float
    finding_type: str  # "conflict" | "repetition"


@dataclass(frozen=True)
class TargetScore:
    """Per-instruction compliance breakdown (Pro tier)."""

    line: int
    file_path: str
    compliance_band: str  # "HIGH" | "MODERATE" | "LOW"
    impact_rank: int
    n_eff: float
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
    weakest_context: str | None = None
    strongest_context: str | None = None


@dataclass(frozen=True)
class FileAnalysis:
    """Per-file server analysis."""

    file: str
    diagnostics: tuple[Diagnostic, ...] = ()
    compliance_band: str = ""
    stats: dict[str, Any] = field(default_factory=dict)


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
    """Read tier from global config (~/.reporails/config.yml)."""
    try:
        from reporails_cli.core.config import get_global_config

        cfg = get_global_config()
        return cfg.tier
    except (ImportError, AttributeError, OSError) as exc:
        logger.debug("Could not read tier from config: %s", exc)
        return ""


def _api_key_from_credentials() -> str:
    """Read API key from ~/.reporails/credentials.yml (set by `ails auth login`)."""
    from pathlib import Path

    try:
        import yaml

        path = Path.home() / ".reporails" / "credentials.yml"
        if not path.exists():
            return ""
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data.get("api_key", "") if isinstance(data, dict) else ""
    except ImportError:
        logger.debug("PyYAML not installed — cannot read credentials")
        return ""
    except (OSError, yaml.YAMLError) as exc:
        logger.debug("Could not read credentials file: %s", exc)
        return ""


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
        self.api_key = api_key or os.environ.get("AILS_API_KEY") or _api_key_from_credentials()
        self.tier = tier or os.environ.get("AILS_TIER") or _tier_from_config() or "free"
        self.timeout = timeout

    def lint(self, ruleset_map: RulesetMap) -> LintResult | None:
        """Run diagnostics on a ruleset map via the API.

        Returns LintResult with report + hints (tier-gated), or None on failure.
        Requires network — diagnostics run server-side only.
        """
        if not self.base_url:
            logger.debug("No server URL configured — diagnostics unavailable offline")
            return None
        return self._lint_remote(ruleset_map)

    def _lint_remote(self, ruleset_map: RulesetMap) -> LintResult | None:
        """POST text-stripped RulesetMap to diagnostic API.

        In production: CLI → Worker (/v1/diagnose, Bearer rr_*) → FastAPI.
        In local dev (AILS_DEV_MODE): CLI → FastAPI directly (/diagnose, X-Tier header).
        """
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed — cannot use remote diagnostics")
            return None

        try:
            payload = _strip_and_serialize(ruleset_map)
            dev_mode = os.environ.get("AILS_DEV_MODE", "").lower() in ("true", "1")

            if dev_mode:
                # Direct to FastAPI — no Worker, no Bearer auth
                url = f"{self.base_url.rstrip('/')}/diagnose"
                headers: dict[str, str] = {"X-Tier": self.tier}
            else:
                # Through Worker — Bearer auth, /v1/diagnose path
                url = f"{self.base_url.rstrip('/')}/v1/diagnose"
                headers = {}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"

            resp = httpx.post(url, json=payload, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return _deserialize_lint_result(resp.json())
        except httpx.TimeoutException:
            logger.debug("Remote diagnostic request timed out after %.1fs", self.timeout)
            return None
        except httpx.HTTPStatusError as exc:
            logger.debug("Remote diagnostic returned HTTP %d: %s", exc.response.status_code, exc)
            return None
        except httpx.HTTPError as exc:
            logger.debug("Remote diagnostic network error: %s", exc)
            return None
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            logger.debug("Remote diagnostic response malformed: %s", exc)
            return None


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
                )
            )
        items.append(
            FileAnalysis(
                file=fa_file,
                diagnostics=tuple(diagnostics),
                compliance_band=fa.get("compliance_band", ""),
                stats=fa.get("stats", {}),
            )
        )
    return tuple(items)


def _deserialize_cross_file(report_data: dict[str, Any]) -> tuple[CrossFileFinding, ...]:
    """Deserialize the cross_file section of the API response."""
    items: list[CrossFileFinding] = []
    _required_keys = ("file_1", "file_2", "line_1", "line_2", "charge_1", "charge_2", "distance", "finding_type")
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
                distance=vals["distance"],
                finding_type=vals["finding_type"],
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
            ts_neff = ts.get("n_eff")
            if any(v is None for v in (ts_line, ts_path, ts_band, ts_rank, ts_neff)):
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
                    n_eff=ts_neff,
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
        return LintResult(report=RulesetReport())

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

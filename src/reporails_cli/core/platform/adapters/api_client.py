"""Client for the reporails diagnostics server.

Sends a text-stripped RulesetMap and deserializes the response into the shared
`dto.diagnostics` shapes. AILS_SERVER_URL overrides the default server.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from reporails_cli.core.platform.adapters.rate_cooldown import active_cooldown, record_cooldown
from reporails_cli.core.platform.adapters.workflow_wire import _opt_int, deserialize_workflow
from reporails_cli.core.platform.contract.errors import (
    ConfigUnreadableError,
    CredentialsUnreadableError,
    PlatformError,
)
from reporails_cli.core.platform.dto.diagnostics import (
    DEFAULT_RETRY_AFTER_S,
    CrossFileCoordinate,
    CrossFileFinding,
    Diagnostic,
    FileAnalysis,
    FunnelError,
    Hint,
    LintResponse,
    LintResult,
    LocalTier,
    QualityResult,
    RulesetReport,
)
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.policy.preflight import parse_error_body, preflight_oversized

logger = logging.getLogger(__name__)

# The diagnostics server used when `AILS_SERVER_URL` is unset.
DEFAULT_SERVER_URL = "https://api.reporails.com"


def _user_agent() -> str:
    """Return `reporails-cli/<version>` for outgoing diagnostic requests.

    Sends a distinct UA instead of the default `python-httpx/*` one.
    """
    try:
        return f"reporails-cli/{version('reporails-cli')}"
    except PackageNotFoundError:
        return "reporails-cli/unknown"


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


def resolve_api_key() -> str:
    """The API key in effect: ``AILS_API_KEY`` when set, else the stored credentials.

    Returns "" when neither holds a key; an unreadable credentials file drops
    to "" with a WARNING.
    """
    return os.environ.get("AILS_API_KEY") or _degrade_on_fault(_api_key_from_credentials, "API key")


def default_server_api_key() -> str:
    """The API key in effect when ``AILS_SERVER_URL`` is unset or the default server, else "".

    A key paired with another server (a local or staging one) is not returned.
    """
    server = os.environ.get("AILS_SERVER_URL", "").strip().rstrip("/")
    if server and server != DEFAULT_SERVER_URL:
        return ""
    return resolve_api_key()


def has_api_key() -> bool:
    """True when an API key is available (env override or stored credentials).

    Client-side affordance gate: distinguishes an authenticated user from an
    anonymous one without consulting the server. This only gates which local
    affordances are offered; the plan itself is whatever the server reports.
    """
    return bool(resolve_api_key())


class AilsClient:
    """Diagnostics client — HTTP to the diagnostics server, local fallback.

    Sends a text-stripped RulesetMap to the server. AILS_SERVER_URL overrides
    the default server. Returns None when the server is unreachable.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        tier: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("AILS_SERVER_URL") or DEFAULT_SERVER_URL
        self.api_key = api_key or resolve_api_key()
        self.tier = tier or os.environ.get("AILS_TIER") or _degrade_on_fault(_tier_from_config, "tier") or "free"
        self.timeout = timeout

    def lint(
        self,
        ruleset_map: RulesetMap,
        local: Sequence[LocalEntry] = (),
        structural_required: int = 0,
        *,
        root: Path,
    ) -> LintResponse:
        """Run diagnostics on a ruleset map via the API.

        `root` is the checked project's own root — the same root the rest of the run
        resolves local paths against — and every
        wire `path` / `local_files` entry rides relative to it, never the terminal's working
        directory. The caller always has it; there is no default.
        `local` holds one entry per reported local finding, and `structural_required`
        is the count of structural rule classes the project is subject to.
        Returns LintResponse — `.result` on 2xx, `.funnel_error` on a tier-aware 4xx or
        local preflight rejection, both None on network failure.
        """
        if not self.base_url:
            logger.debug("No server URL configured — diagnostics unavailable offline")
            return LintResponse()
        return self._lint_remote(ruleset_map, local, structural_required, root)

    def _lint_remote(
        self,
        ruleset_map: RulesetMap,
        local: Sequence[LocalEntry],
        structural_required: int,
        root: Path,
    ) -> LintResponse:
        """POST the projected RulesetMap to the diagnostic backend."""
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed — cannot use remote diagnostics")
            return LintResponse()

        from reporails_cli.core.platform.adapters.payload import encode_msgpack, project_local, project_payload

        payload = project_payload(ruleset_map, root)
        if local:
            payload.update(project_local(local, [f["path"] for f in payload["files"]], root))
        if structural_required:
            payload["structural_required"] = structural_required
        if not payload.get("files"):
            logger.warning("No instruction files in payload — skipping remote diagnostics")
            return LintResponse()
        cap_error = preflight_oversized(payload, has_api_key=bool(self.api_key))
        if cap_error is not None:
            logger.warning("Preflight rejected payload: %s (%d/%d)", cap_error.error, cap_error.size, cap_error.limit)
            return LintResponse(funnel_error=cap_error)
        cooldown = active_cooldown(self.base_url, self.api_key)
        if cooldown is not None:
            logger.debug("Rate limit still in effect for %ds — skipping remote diagnostics", cooldown.reset_in)
            return LintResponse(funnel_error=cooldown)
        body = encode_msgpack(payload)
        return self._post_payload(httpx, body)

    def _status_error(self, response: Any) -> FunnelError:
        """The funnel error for a non-2xx reply: a busy or slow server, a tier-aware 4xx, or a plain HTTP error."""
        status = response.status_code
        retry_after = getattr(response, "headers", {}).get("Retry-After")
        funnel_err = parse_error_body(status, response.text, retry_after)
        if funnel_err is not None:
            logger.log(
                logging.WARNING if funnel_err.retryable else logging.DEBUG,
                "Server returned %d %s for tier=%s",
                status,
                funnel_err.error,
                funnel_err.tier,
            )
            record_cooldown(self.base_url, self.api_key, funnel_err)
            return funnel_err
        logger.warning("Remote diagnostic returned HTTP %d (no parseable body)", status)
        return FunnelError(error="http_error", status=status, message=f"Diagnostics server returned HTTP {status}")

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
            return LintResponse(funnel_error=FunnelError(error="timeout", reset_in=DEFAULT_RETRY_AFTER_S))
        except httpx.HTTPStatusError as exc:
            return LintResponse(funnel_error=self._status_error(exc.response))
        except httpx.HTTPError as exc:
            logger.warning("Remote diagnostic network error: %s", exc)
            return LintResponse(
                funnel_error=FunnelError(
                    error="network_error",
                    message="Could not reach the diagnostics server",
                )
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            logger.warning("Remote diagnostic response malformed: %s", exc)
            return LintResponse(
                funnel_error=FunnelError(
                    error="malformed_response",
                    message="Diagnostics server returned an unreadable response",
                )
            )


# ──────────────────────────────────────────────────────────────────
# WIRE FORMAT — serialization for API transport
# ──────────────────────────────────────────────────────────────────

# Encoding tables — map semantic names to wire-format short codes.
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


def _deserialize_per_file(report_data: dict[str, Any]) -> tuple[FileAnalysis, ...]:
    """Deserialize the per_file section of the API response."""
    items: list[FileAnalysis] = []
    for fa in report_data.get("per_file", []):
        if not isinstance(fa, dict):
            logger.warning("Skipping per_file entry that is not an object: %s", fa)
            continue
        fa_file: Any = fa.get("file")
        if fa_file is None:
            logger.warning("Skipping per_file entry with missing 'file' key")
            continue
        diagnostics: list[Diagnostic] = []
        for d in fa.get("diagnostics", []):
            if not isinstance(d, dict):
                logger.warning("Skipping diagnostic that is not an object in file %s: %s", fa_file, d)
                continue
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
                    impact_tier=d.get("impact_tier", ""),
                    pi=_opt_int(d.get("pi")),
                )
            )
        items.append(
            FileAnalysis(
                file=fa_file,
                diagnostics=tuple(diagnostics),
                stats=fa.get("stats", {}),
                display_score=fa.get("display_score"),
            )
        )
    return tuple(items)


def _deserialize_cross_file(report_data: dict[str, Any]) -> tuple[CrossFileFinding, ...]:
    """Deserialize the cross_file section of the API response."""
    items: list[CrossFileFinding] = []
    _required_keys = ("file_1", "file_2", "line_1", "line_2", "finding_type")
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
                finding_type=vals["finding_type"],
            )
        )
    return tuple(items)


def _deserialize_local_tiers(report_data: dict[str, Any]) -> tuple[LocalTier, ...]:
    """Deserialize the local_tiers section of the report; a malformed row is skipped."""
    raw = report_data.get("local_tiers")
    rows: list[LocalTier] = []
    for row in raw if isinstance(raw, list) else ():
        if not isinstance(row, dict):
            logger.warning("Skipping local_tiers entry that is not an object: %s", row)
            continue
        file, rule, line, tier = (row.get(k) for k in ("file", "rule", "line", "impact_tier"))
        if not (isinstance(file, str) and isinstance(rule, str) and isinstance(tier, str) and tier):
            logger.warning("Skipping local_tiers entry with missing field: %s", row)
            continue
        if not isinstance(line, int) or isinstance(line, bool):
            logger.warning("Skipping local_tiers entry with a non-integer line: %s", row)
            continue
        rows.append(LocalTier(file=file, rule=rule, line=line, impact_tier=tier))
    return tuple(rows)


def _deserialize_quality(report_data: dict[str, Any]) -> QualityResult | None:
    """Deserialize the quality section of the API response; None when the reply carries none."""
    q_data = report_data.get("quality")
    if not isinstance(q_data, dict):
        return None
    return QualityResult(display_score=q_data.get("display_score"))


def _deserialize_hints(data: dict[str, Any]) -> tuple[Hint, ...]:
    """Deserialize the hints section of the API response."""
    items: list[Hint] = []
    for h in data.get("hints", []):
        h_file = h.get("file")
        h_type = h.get("diagnostic_type")
        h_count = h.get("count")
        if any(v is None for v in (h_file, h_type, h_count)):
            logger.warning("Skipping hint entry with missing required field: %s", h)
            continue
        items.append(
            Hint(
                file=h_file,
                diagnostic_type=h_type,
                count=h_count,
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
    """Deserialize API JSON response to LintResult; a body that is not an object is a malformed response."""
    if not isinstance(data, dict):
        raise ValueError(f"response body is {type(data).__name__}, not an object")
    report_data = data.get("report")
    if not isinstance(report_data, dict):
        logger.warning("API response missing 'report' key or not a dict")
        # Forward the server tier even on a malformed report — dropping it here silently
        # relabels a pro/anonymous session as the default 'free' downstream.
        return LintResult(report=RulesetReport(), tier=str(data.get("tier") or ""))

    report = RulesetReport(
        per_file=_deserialize_per_file(report_data),
        local_tiers=_deserialize_local_tiers(report_data),
        cross_file=_deserialize_cross_file(report_data),
        quality=_deserialize_quality(report_data),
    )

    return LintResult(
        report=report,
        hints=_deserialize_hints(data),
        cross_file_coordinates=_deserialize_cross_file_coordinates(data),
        # A response that names no tier stays EMPTY, never "free".
        tier=str(data.get("tier") or ""),
        workflow=deserialize_workflow(data),
    )

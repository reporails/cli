"""Tests for formatters/json.py — JSON output format."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.diagnostics import CrossFileCoordinate, FunnelError, Hint, QualityResult
from reporails_cli.core.platform.dto.models import Level
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem
from reporails_cli.formatters.json import format_combined_result


def _result(**overrides: object) -> CombinedResult:
    defaults: dict[str, object] = {
        "findings": (),
        "cross_file": (),
        "quality": None,
        "per_file_analysis": (),
        "stats": CombinedStats(total_findings=0, errors=0, warnings=0, infos=0),
        "offline": True,
        "hints": (),
        "cross_file_coordinates": (),
    }
    defaults.update(overrides)
    return CombinedResult(**defaults)  # type: ignore[arg-type]


class TestQualityNullDisplayScore:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_unscored_project_emits_null_not_fabricated_floor(self) -> None:
        # The api now returns `display_score: null` for a project where no file had
        # any charged atoms (previously it fabricated the floor value 1.0). The JSON
        # formatter must pass that null through verbatim, not raise on `float(None)`.
        quality = QualityResult(display_score=None)
        data = format_combined_result(_result(quality=quality))
        assert data["quality"] is None
        assert data["quality"] != 1.0


class TestServerErrorSection:
    """A server rejection, timeout, or network failure must
    reach `--format json` as a distinguishable `server_error` object, not read
    identically to a designed offline run (`offline: true`, no reason)."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_successful_result_serializes_server_error_null(self) -> None:
        data = format_combined_result(_result(offline=False, tier="pro"))
        assert data["server_error"] is None
        assert data["offline"] is False

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_offline_by_design_serializes_server_error_null(self) -> None:
        """No server call at all (offline=True, no funnel error) is not a rejection."""
        data = format_combined_result(_result(offline=True))
        assert data["server_error"] is None
        assert data["offline"] is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_401_invalid_api_key_populates_server_error(self) -> None:
        server_error = FunnelError(error="unknown_error", message="API key not recognized", status=401)
        data = format_combined_result(_result(offline=True, server_error=server_error))
        assert data["offline"] is True  # `offline` semantics unchanged by this fix
        assert data["server_error"] == {
            "status": 401,
            "error": "unknown_error",
            "message": "API key not recognized",
            "tier": "",
            "upgrade_url": "",
            "retryable": False,
            "retry_after": None,
        }

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_413_payload_too_large_carries_upgrade_url(self) -> None:
        server_error = FunnelError(
            error="payload_too_large",
            tier="free",
            status=413,
            upgrade_url="https://reporails.com/account?utm_source=cli",
        )
        data = format_combined_result(_result(offline=True, server_error=server_error))
        se = data["server_error"]
        assert se["status"] == 413
        assert se["error"] == "payload_too_large"
        assert se["tier"] == "free"
        assert se["upgrade_url"] == "https://reporails.com/account?utm_source=cli"
        assert se["message"]  # CTA text present

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_timeout_has_no_http_status(self) -> None:
        server_error = FunnelError(error="timeout", reset_in=10)
        data = format_combined_result(_result(offline=True, server_error=server_error))
        se = data["server_error"]
        assert se["status"] is None
        assert se["error"] == "timeout"
        assert se["message"] == "The diagnostics request took too long. Try again in 10 seconds."

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_message_carries_no_terminal_rich_markup(self) -> None:
        """`format_server_error` put `format_cta`'s raw string --
        which carries `[link=...][bold]...[/bold][/link]` when a CTA URL resolves -- straight
        into the machine `server_error.message`. A CI job or agent reading the JSON literally
        saw the bracket tags. `plain_cta` (the single markup-free serializer) must be the
        source instead."""
        server_error = FunnelError(
            error="rate_limit_exceeded", tier="free", limit=5, upgrade_url="https://reporails.com/account"
        )
        data = format_combined_result(_result(offline=True, server_error=server_error))
        message = data["server_error"]["message"]
        assert "[link=" not in message
        assert "[bold]" not in message
        assert "[/bold]" not in message
        assert "[/link]" not in message

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_server_supplied_message_with_unmatched_closing_tag_does_not_crash(self) -> None:
        """A server-supplied `message` is untrusted text. An unmatched closing tag like
        `[/bold]` must not raise `rich.errors.MarkupError` when it enters the JSON
        `server_error.message` field, and must survive as literal text, not be swallowed."""
        server_error = FunnelError(error="unknown_error", tier="free", message="Server said [/bold] oops")
        data = format_combined_result(_result(offline=True, server_error=server_error))
        assert "[/bold]" in data["server_error"]["message"]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_server_supplied_emoji_shortcode_stays_literal(self) -> None:
        """A server `message` containing a `:name:` shortcode must render as literal text
        in machine-consumed JSON output, never substituted into an emoji glyph."""
        server_error = FunnelError(error="unknown_error", tier="free", message="Uh oh :smile: try again")
        data = format_combined_result(_result(offline=True, server_error=server_error))
        assert ":smile:" in data["server_error"]["message"]


class TestProSection:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_pro_section_present_with_hints(self) -> None:
        hints = (
            Hint(file="a.md", diagnostic_type="CORE:C:0044", count=5, error_count=2, warning_count=3),
            Hint(file="b.md", diagnostic_type="CORE:C:0047", count=3, error_count=0, warning_count=3),
        )
        data = format_combined_result(_result(hints=hints))
        assert "pro" in data
        assert data["pro"]["count"] == 8
        assert data["pro"]["errors"] == 2
        assert data["pro"]["warnings"] == 6

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_pro_section_without_hints(self) -> None:
        data = format_combined_result(_result())
        assert "pro" not in data


class TestCrossFileCoordinatesSection:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_coordinates_serialized(self) -> None:
        coords = (
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="conflict", count=2),
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="repetition", count=1),
        )
        data = format_combined_result(_result(cross_file_coordinates=coords))
        assert "cross_file_coordinates" in data
        assert len(data["cross_file_coordinates"]) == 2
        assert data["cross_file_coordinates"][0]["type"] == "conflict"
        assert data["cross_file_coordinates"][0]["count"] == 2

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_coordinates_section_when_empty(self) -> None:
        data = format_combined_result(_result())
        assert "cross_file_coordinates" not in data


class TestLeverageAndRegime:
    """Additive `leverage` (per finding) + `regime` (per file) keys."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_graded_finding_keeps_leverage_without_touching_severity(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(
                file="a.md",
                line=1,
                severity="warning",
                rule="CORE:C:0044",
                message="scatter",
                impact_tier="conditional",
            ),
            FindingItem(file="a.md", line=2, severity="info", rule="bold", message="bold", impact_tier="cosmetic"),
        )
        data = format_combined_result(_result(findings=findings))
        by_rule = {e["rule"]: e for e in data["files"]["a.md"]["findings"]}
        # `bold` canonicalizes to CORE:E:0003 on the wire (raw token kept under `label`).
        assert by_rule["CORE:C:0044"]["leverage"] == "conditional"
        assert by_rule["CORE:E:0003"]["leverage"] == "cosmetic"
        assert by_rule["CORE:E:0003"]["label"] == "bold"
        assert by_rule["CORE:C:0044"]["severity"] == "warning"
        assert by_rule["CORE:E:0003"]["severity"] == "info"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_ungraded_finding_has_no_leverage_key(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="a.md", line=1, severity="warning", rule="CORE:C:0042", message="x"),
            FindingItem(
                file="a.md", line=2, severity="warning", rule="CORE:C:0044", message="y", impact_tier="gate_mover"
            ),
        )
        data = format_combined_result(_result(findings=findings))
        graded = {e["rule"]: ("leverage" in e) for e in data["files"]["a.md"]["findings"]}
        assert graded == {"CORE:C:0042": False, "CORE:C:0044": True}
        assert '"leverage"' not in json.dumps(format_combined_result(_result(findings=findings[:1])))

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_per_file_regime_added_when_analysis_present(self) -> None:
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),)
        per_file = (
            FileAnalysis(
                file="a.md",
                stats={"triage_tier": "partial"},
            ),
        )
        data = format_combined_result(_result(findings=findings, per_file_analysis=per_file))
        regime = data["files"]["a.md"]["regime"]
        # Public JSON exposes only the opaque triage tier token.
        assert regime == {"triage_tier": "partial"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_retired_strict_token_drops_the_regime_key(self) -> None:
        """A server still emitting the retired "strict" wire token degrades to
        the neutral view — no `regime` key rather than an honored "strict"."""
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),)
        per_file = (
            FileAnalysis(
                file="a.md",
                stats={"triage_tier": "strict"},
            ),
        )
        data = format_combined_result(_result(findings=findings, per_file_analysis=per_file))
        assert "regime" not in data["files"]["a.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_regime_keyed_against_passed_project_root(self) -> None:
        """Server `per_file` paths are absolute; the regime must relativize them
        against the run's `project_root` (not cwd) so single-path scans attach
        the regime to the matching finding key instead of dropping it."""
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis
        from reporails_cli.core.platform.runtime.merger import FindingItem

        root = Path("/tmp/proj")
        findings = (
            FindingItem(file=".claude/rules/x.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),
        )
        per_file = (
            FileAnalysis(
                file="/tmp/proj/.claude/rules/x.md",
                stats={"triage_tier": "partial"},
            ),
        )
        result = _result(findings=findings, per_file_analysis=per_file)
        # With the correct root the absolute per_file path relativizes to the
        # finding key, so the regime attaches.
        data = format_combined_result(result, project_root=root)
        assert "regime" in data["files"][".claude/rules/x.md"]
        # With the wrong root (cwd) the absolute path falls outside it, the key
        # diverges, and the regime drops — the bug single-file scans hit.
        stray = format_combined_result(result)
        assert "regime" not in stray["files"][".claude/rules/x.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_surface_health_keyed_against_passed_project_root(self) -> None:
        """Surface scores must relativize absolute server `per_file` paths against the run's
        `project_root` too (not just regime) — the MCP path where target != cwd."""
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis
        from reporails_cli.core.platform.runtime.merger import FindingItem

        root = Path("/tmp/proj")
        findings = (FindingItem(file="CLAUDE.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),)
        per_file = (
            FileAnalysis(
                file="/tmp/proj/CLAUDE.md",
                display_score=8.0,
                stats={"triage_tier": "partial"},
            ),
        )
        result = _result(findings=findings, per_file_analysis=per_file)
        scored = {
            s["name"]: s["score"] for s in format_combined_result(result, project_root=root).get("surface_health", [])
        }
        assert scored.get("Main") == 8.0
        # Wrong root (cwd): the absolute per_file path misroutes out of Main, the score drops.
        stray = {s["name"]: s["score"] for s in format_combined_result(result).get("surface_health", [])}
        assert stray.get("Main") != 8.0

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_surface_health_routes_generic_to_imported(self) -> None:
        """JSON surface_health must route @-import (`generic`) files to the Imported surface
        when file_type_by_path is supplied — matching the text view (was text-only)."""
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis
        from reporails_cli.core.platform.runtime.merger import FindingItem

        root = Path("/tmp/proj")
        findings = (FindingItem(file="docs/imp.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),)
        per_file = (FileAnalysis(file="/tmp/proj/docs/imp.md", display_score=6.0),)
        result = _result(findings=findings, per_file_analysis=per_file)
        with_ft = format_combined_result(result, project_root=root, file_type_by_path={"docs/imp.md": "generic"})
        assert "Imported" in {s["name"] for s in with_ft.get("surface_health", [])}
        # Without the map the file routes by path, not to Imported.
        without_ft = format_combined_result(result, project_root=root)
        assert "Imported" not in {s["name"] for s in without_ft.get("surface_health", [])}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_regime_key_when_offline(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="warning", rule="CORE:C:0044", message="x"),)
        data = format_combined_result(_result(findings=findings))
        assert "regime" not in data["files"]["a.md"]


class TestTierExposure:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_present_at_top_level(self) -> None:
        data = format_combined_result(_result(tier="pro"))
        assert data["tier"] == "pro"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_empty_when_offline(self) -> None:
        data = format_combined_result(_result())
        assert data["tier"] == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_pass_through_for_anonymous(self) -> None:
        data = format_combined_result(_result(tier="anonymous"))
        assert data["tier"] == "anonymous"


class TestPerFindingCategory:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "rule_id,expected",
        [
            ("CORE:S:0001", "structure"),
            ("CORE:D:0002", "direction"),
            ("CORE:C:0053", "coherence"),
            ("CORE:E:0004", "efficiency"),
            ("CORE:M:0001", "maintenance"),
            ("CORE:G:0001", "governance"),
            ("CLAUDE:S:0012", "structure"),
        ],
    )
    def test_category_derived_from_rule_id(self, rule_id: str, expected: str) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="error", rule=rule_id, message="x"),)
        data = format_combined_result(_result(findings=findings))
        entry = data["files"]["a.md"]["findings"][0]
        assert entry["category"] == expected

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_bare_token_canonicalized_to_category(self) -> None:
        """Bare-token rule ids are canonicalized on the wire, so they
        now carry a category and preserve the raw token under `label`."""
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="warning", rule="format", message="x"),)
        data = format_combined_result(_result(findings=findings))
        entry = data["files"]["a.md"]["findings"][0]
        assert entry["rule"] == "CORE:E:0003"
        assert entry["label"] == "format"
        assert entry["category"] == "efficiency"


class TestSurfaceCategoryBreakdown:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_breakdown_sums_to_finding_count_for_well_formed_rules(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:C:0001", message="x"),
            FindingItem(file="CLAUDE.md", line=2, severity="warning", rule="CORE:C:0002", message="x"),
            FindingItem(file="CLAUDE.md", line=3, severity="error", rule="CORE:S:0001", message="x"),
        )
        data = format_combined_result(_result(findings=findings))
        sh = data["surface_health"][0]
        breakdown = sh["category_breakdown"]
        assert sum(breakdown.values()) == sh["finding_count"]
        assert breakdown == {"coherence": 2, "structure": 1}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_breakdown_includes_canonicalized_bare_tokens(self) -> None:
        """Bare-token rule ids are canonicalized before the breakdown,
        so the breakdown now sums to finding_count instead of dropping them."""
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:C:0001", message="x"),
            FindingItem(file="CLAUDE.md", line=2, severity="warning", rule="format", message="x"),
        )
        data = format_combined_result(_result(findings=findings))
        sh = data["surface_health"][0]
        assert sh["finding_count"] == 2
        assert sum(sh["category_breakdown"].values()) == 2


class TestTopRulesSeverityBreakdown:
    """`top_rules[].severity` is the rule's worst severity sitting beside its *total* count:
    a rule with 1 error and 69 warnings read
    `{"severity": "error", "count": 70}`, which a coding agent misread as "70 errors"
    against `stats.errors: 2`. `errors`/`warnings` disambiguate without dropping the
    existing `severity`/`count` fields."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_top_rules_entry_carries_its_own_error_and_warning_counts(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="a.md", line=1, severity="error", rule="CORE:C:0042", message="x"),
            *[
                FindingItem(file="a.md", line=n, severity="warning", rule="CORE:C:0042", message="x")
                for n in range(2, 71)
            ],
        )
        data = format_combined_result(_result(findings=findings))
        entry = next(r for r in data["top_rules"] if r["rule"] == "CORE:C:0042")
        assert entry["count"] == 70
        assert entry["severity"] == "error"
        assert entry["errors"] == 1
        assert entry["warnings"] == 69

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_top_rules_all_warnings_reads_zero_errors(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="a.md", line=1, severity="warning", rule="CORE:S:0001", message="x"),
            FindingItem(file="a.md", line=2, severity="warning", rule="CORE:S:0001", message="x"),
        )
        data = format_combined_result(_result(findings=findings))
        entry = next(r for r in data["top_rules"] if r["rule"] == "CORE:S:0001")
        assert entry["errors"] == 0
        assert entry["warnings"] == 2


class TestContentChecksSkippedFlag:
    """With a partial model set (e.g. `AILS_MODEL_OFFLINE=1` and no model on disk), the
    check scores silently on the tokenize-time lexical charge instead of the bundled
    classification models, with nothing in the JSON saying so — a CI consumer reads a
    degraded run's smaller finding count as a cleaner project. `content_checks_skipped`
    reports the same predicate the mapper's charge stage itself reads to decide whether to
    run the encoders (`core.mapper.bio_tagger.multislot_available`)."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_flag_true_when_classification_models_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: False)
        data = format_combined_result(_result())
        assert data["content_checks_skipped"] is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_flag_false_when_classification_models_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
        data = format_combined_result(_result())
        assert data["content_checks_skipped"] is False


class TestContentChecksSkippedWhenMappingFailed:
    """A run whose files could not be mapped ran no content checks, whatever models sit on disk."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_flag_true_when_the_run_could_not_map_its_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
        assert format_combined_result(_result(level=Level.L2), ruleset_map=None)["content_checks_skipped"] is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_flag_false_when_the_run_mapped_its_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
        assert format_combined_result(_result(), ruleset_map=object())["content_checks_skipped"] is False

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_flag_false_for_a_project_with_no_instruction_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
        data = format_combined_result(CombinedResult(), ruleset_map=None)
        assert data["content_checks_skipped"] is False


class TestConventionMarker:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_convention_findings_are_kept_and_marked(self) -> None:
        """Every finding stays in the JSON; a documentation convention carries `convention: true`."""
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(
                file="CLAUDE.md", line=1, severity="warning", rule="CORE:C:0005", message="Missing", convention=True
            ),
            FindingItem(file="CLAUDE.md", line=3, severity="warning", rule="CORE:S:0010", message="Count"),
        )
        data = format_combined_result(_result(findings=findings, stats=CombinedStats(total_findings=2, warnings=2)))
        rows = data["files"]["CLAUDE.md"]["findings"]
        assert len(rows) == 2
        assert [r.get("convention", False) for r in rows] == [True, False]
        assert data["stats"]["total_findings"] == 2


class TestOverlapPartner:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_overlap_finding_names_its_partner_file(self, tmp_path: Path) -> None:
        item = FindingItem(
            file="CLAUDE.md",
            line=3,
            severity="warning",
            rule="CORE:C:0001",
            message="Overlapping instructions",
            source="server",
            partner_file=str(tmp_path / "docs" / "AGENTS.md"),
            partner_line=7,
            overlap_pct=40,
        )
        data = format_combined_result(_result(findings=(item,)), project_root=tmp_path)
        entry = data["files"]["CLAUDE.md"]["findings"][0]
        assert entry["partner_file"] == "docs/AGENTS.md"
        assert entry["partner_line"] == 7
        assert entry["overlap_pct"] == 40

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_finding_without_a_partner_carries_no_partner_keys(self, tmp_path: Path) -> None:
        item = FindingItem(file="CLAUDE.md", line=3, severity="warning", rule="CORE:C:0001", message="m")
        data = format_combined_result(_result(findings=(item,)), project_root=tmp_path)
        entry = data["files"]["CLAUDE.md"]["findings"][0]
        assert not {"partner_file", "partner_line", "overlap_pct"} & entry.keys()

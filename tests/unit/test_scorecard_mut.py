"""Mutation-closing tests for `formatters/text/scorecard.py`.

Each test pins a branch, count, or threshold that the mutation probe found
uncovered — the assertion reddens the moment the injected operator bug returns.
Fakes follow the duck-typed-dataclass + `console.capture()` pattern already used
in test_scorecard.py. Cosmetic display constants (exact label text with no
behavioral contract) are left in the equivalent bucket, not decorated here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from reporails_cli.formatters.text.display_constants import element_namer
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    SurfaceHealth,
    _count_categories,
    _render_cross_file_counts,
    _render_scope,
    _render_surface_health,
    _render_verdict_block,
    compute_score,
    compute_surface_scores,
    console,
    print_scorecard,
)

# ── duck-typed fakes ──────────────────────────────────────────────────


@dataclass
class _Quality:
    display_score: float


@dataclass
class _Stats:
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    total_findings: int = 0
    cross_file_repetitions: int = 0
    cross_file_overlaps: int = 0


@dataclass
class _Finding:
    severity: str = "info"
    rule: str = "CORE:S:0001"
    message: str = "example finding"
    file: str = "CLAUDE.md"
    convention: bool = False


@dataclass
class _Cross:
    finding_type: str
    file_1: str = ""
    file_2: str = ""


@dataclass
class _FileRec:
    path: str
    type: str = "generic"
    skill: str = ""
    agent: str = "claude"


@dataclass
class _Map:
    files: tuple = ()


@dataclass
class _Result:
    quality: _Quality | None = None
    stats: _Stats = field(default_factory=_Stats)
    findings: tuple = ()
    hints: object = None
    cross_file: tuple = ()
    cross_file_coordinates: tuple = ()
    per_file_analysis: tuple = ()
    server_error: object = None


def _capture(fn, *args, **kwargs) -> str:
    with console.capture() as cap:
        fn(*args, **kwargs)
    return " ".join(cap.get().split())


# ── compute_score ─────────────────────────────────────────────────────


class TestComputeScore:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_quality_flag_returns_zero(self) -> None:
        # has_quality=False must short-circuit to 0.0 even when a quality object is
        # present; the `and -> or` mutation would return the display_score instead.
        result = _Result(quality=_Quality(display_score=9.0))
        assert compute_score(result, has_quality=False) == 0.0  # kills L49 and -> or


# ── compute_surface_scores: error count ───────────────────────────────


class TestSurfaceErrorCount:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_error_count_matches_error_findings(self) -> None:
        result = _Result(
            findings=(
                _Finding(severity="error"),
                _Finding(severity="warning"),
                _Finding(severity="info"),
            )
        )
        surfaces = compute_surface_scores(result, project_root=".")
        main = next(s for s in surfaces if s.name == "Main")
        assert main.errors == 1  # kills L176 == -> != (would count non-errors)
        assert main.infos == 1  # kills L178 == -> != (would count non-infos)


# ── _count_categories ─────────────────────────────────────────────────


class TestCountCategories:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_known_category_counted(self) -> None:
        # A structure-category rule id must land in the breakdown. `f.rule or ""`
        # (or -> and) would blank the id; `category is None` (is -> is not) would
        # skip the known category instead of the unknown ones.
        findings = [_Finding(rule="CORE:S:0001"), _Finding(rule="CORE:S:0002")]
        breakdown = _count_categories(findings)
        assert breakdown == {"structure": 2}  # kills L238 or -> and, L242 is -> is not


# ── _render_surface_health suppression ────────────────────────────────


class TestRenderSurfaceHealth:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_single_surface_renders_nothing(self) -> None:
        # A lone surface is suppressed (the top Score covers it). `<= -> <` would
        # render the single bar.
        one = [SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=0, item_count=1)]
        assert _capture(_render_surface_health, one) == ""  # kills L307 <= -> <


# ── _render_verdict_block ─────────────────────────────────────────────


class TestVerdictBlock:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_quality_renders_na(self) -> None:
        # has_quality=False must render the n/a line, not a score; `and -> or` would
        # try to render the score from the present quality object.
        result = _Result(quality=_Quality(display_score=9.0), stats=_Stats())
        out = _capture(_render_verdict_block, result, False, 0, 0.0)
        assert "n/a" in out  # kills L342 and -> or

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_unscored_project_renders_na_without_raising(self) -> None:
        # `quality` is present (has_quality=True) but `display_score` is `None` — a
        # project where no file had any charged atoms. Must render the distinct
        # "no scorable content" line, not raise `TypeError: float() ... NoneType`,
        # and must NOT read as the offline "server diagnostics unavailable" case.
        result = _Result(quality=_Quality(display_score=None), stats=_Stats())
        out = _capture(_render_verdict_block, result, True, 0, 0.0)
        assert "n/a" in out
        assert "no scorable content" in out
        assert "server diagnostics unavailable" not in out


# ── _render_scope ─────────────────────────────────────────────────────


class TestRenderScope:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_capabilities_shown_by_default(self) -> None:
        # Called without has_surface_health: the default False must render the
        # capabilities line; the default-True mutation suppresses it.
        scope = ScopeInfo(type_str="2 files")
        out = _capture(_render_scope, scope)
        assert "capabilities" in out  # kills L401 default False -> True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_capabilities_suppressed_with_surface_health(self) -> None:
        # type_str present but surface health rendered elsewhere -> no capabilities
        # line. `and -> or` would print it anyway.
        scope = ScopeInfo(type_str="2 files")
        out = _capture(_render_scope, scope, has_surface_health=True)
        assert "capabilities" not in out  # kills L406 and -> or

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_directive_line_shown(self) -> None:
        # n_dir set, n_prose 0: `or` renders the directive/prose line; `and` (0)
        # would suppress it.
        scope = ScopeInfo(type_str="", n_dir=5, n_prose=0, n_atoms=5)
        out = _capture(_render_scope, scope)
        assert "directive" in out  # kills L409 or -> and

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_constraint_line_shown(self) -> None:
        # n_con set, n_amb 0: `or` renders the constraint line; `and` (0) suppresses.
        scope = ScopeInfo(type_str="", n_con=3, n_amb=0, n_atoms=3)
        out = _capture(_render_scope, scope)
        assert "constraint" in out  # kills L412 or -> and


# ── _render_cross_file_counts ─────────────────────────────────────────


class TestCrossFileCounts:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_repetition_count_read_from_stats(self) -> None:
        # The line renders `stats.cross_file_repetitions` verbatim — the same
        # number the JSON envelope carries — not a re-count of the rows.
        result = _Result(
            stats=_Stats(cross_file_repetitions=2),
            cross_file=(_Cross("repetition"), _Cross("repetition")),
        )
        out = _capture(_render_cross_file_counts, result)
        assert "2 cross-file repetitions" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_count_survives_without_detailed_rows(self) -> None:
        # Aggregate-only run: no detailed rows, count still rendered.
        result = _Result(stats=_Stats(cross_file_repetitions=16))
        out = _capture(_render_cross_file_counts, result)
        assert "16 cross-file repetitions" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_singular_repetition_not_pluralized(self) -> None:
        # Exactly one repetition -> singular; `!= -> ==` would pluralize it.
        result = _Result(stats=_Stats(cross_file_repetitions=1), cross_file=(_Cross("repetition"),))
        out = _capture(_render_cross_file_counts, result)
        assert "1 cross-file repetition" in out
        assert "repetitions" not in out  # kills the `!= -> ==` pluralization mutant

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_zero_repetitions_prints_nothing(self) -> None:
        out = _capture(_render_cross_file_counts, _Result())
        assert out == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_overlap_line_names_the_three_most_shared_pairs(self) -> None:
        # Pairs ranked by shared-instruction rows; the fourth and fifth are counted, not named.
        rows = tuple(
            _Cross("overlap", f"{f1}.md", f"{f2}.md")
            for f1, f2, n in (("a", "b", 1), ("c", "d", 5), ("e", "f", 3), ("g", "h", 2), ("i", "j", 1))
            for _ in range(n)
        )
        out = _capture(_render_cross_file_counts, _Result(stats=_Stats(cross_file_overlaps=5), cross_file=rows))
        assert out == (
            "5 element pairs overlap in topic \u2014 keep each topic in one file "
            "c.md \u2194 d.md e.md \u2194 f.md g.md \u2194 h.md "
            "+2 more pairs \u00b7 ails check -v shows each file's overlaps"
        )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_pairs_name_harness_elements_collapse_and_group(self, tmp_path) -> None:
        def rec(path, type_, skill=""):
            return _FileRec(str(tmp_path / path), type_, str(tmp_path / skill) if skill else "")

        files = (
            rec(".claude/skills/audit-checks/SKILL.md", "skills", ".claude/skills/audit-checks"),
            rec(".claude/skills/audit-checks/ref.md", "skills", ".claude/skills/audit-checks"),
            rec(".claude/skills/tighten-language/SKILL.md", "skills", ".claude/skills/tighten-language"),
            rec(".claude/skills/write-rule/SKILL.md", "skills", ".claude/skills/write-rule"),
            rec(".claude/agents/lead.md", "agents"),
            rec("CLAUDE.md", "main"),
            rec("AGENTS.md", "main"),
            rec("docs/x.md", "generic"),
        )
        a1, a2 = ".claude/skills/audit-checks/SKILL.md", ".claude/skills/audit-checks/ref.md"
        tl, wr = ".claude/skills/tighten-language/SKILL.md", ".claude/skills/write-rule/SKILL.md"
        ag = ".claude/agents/lead.md"
        pairs = [
            (a1, tl, 4),
            (a2, tl, 3),
            (a1, wr, 2),
            (tl, wr, 2),
            (ag, "CLAUDE.md", 1),
            (ag, a1, 1),
            ("AGENTS.md", "docs/x.md", 1),
        ]
        rows = tuple(_Cross("overlap", str(tmp_path / x), str(tmp_path / y)) for x, y, n in pairs for _ in range(n))
        result = _Result(stats=_Stats(cross_file_overlaps=7), cross_file=rows)
        out = _capture(_render_cross_file_counts, result, tmp_path, element_namer(_Map(files), tmp_path))
        assert out == (
            "6 element pairs overlap in topic \u2014 keep each topic in one file "
            "audit-checks (skill) \u2194 tighten-language, write-rule, lead (agent) "
            "tighten-language (skill) \u2194 write-rule "
            "lead (agent) \u2194 CLAUDE.md "
            "+1 more pair \u00b7 ails check -v shows each file's overlaps"
        )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_overlap_pairs_are_named_relative_to_the_project(self, tmp_path) -> None:
        rows = (_Cross("overlap", str(tmp_path / "CLAUDE.md"), str(tmp_path / ".claude/skills/qa/SKILL.md")),)
        result = _Result(stats=_Stats(cross_file_overlaps=1), cross_file=rows)
        out = _capture(_render_cross_file_counts, result, tmp_path)
        assert out.endswith(".claude/skills/qa/SKILL.md \u2194 CLAUDE.md")

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_aggregate_only_run_counts_pairs_without_naming_them(self) -> None:
        # The Cross-file section already lists every coordinate pair; the scorecard
        # must not name them a second time in another path form.
        coords = (_Cross("overlap", "a.md", "b.md"),)
        result = _Result(stats=_Stats(cross_file_overlaps=1), cross_file_coordinates=coords)
        out = _capture(_render_cross_file_counts, result)
        assert out == "1 element pair overlaps in topic \u2014 keep each topic in one file"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_single_overlap_pair_reads_singular(self) -> None:
        rows = (_Cross("overlap", "a.md", "b.md"),)
        out = _capture(_render_cross_file_counts, _Result(stats=_Stats(cross_file_overlaps=1), cross_file=rows))
        assert "1 element pair overlaps in topic" in out
        assert "more" not in out


# ── print_scorecard integration (multi-surface gating) ────────────────


def _full_result() -> _Result:
    return _Result(quality=_Quality(display_score=8.0), stats=_Stats(total_findings=0))


class TestPrintScorecardGating:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_imported_surface_omits_imported_caption(self) -> None:
        # Surface set with NO Imported surface -> the "Imported files" caption must
        # not render; `== -> !=` on the any() would print it.
        surfaces = [
            SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=0, item_count=1),
            SurfaceHealth(name="Nested", score=7.0, file_count=1, finding_count=0, item_count=1),
        ]
        out = _capture(
            print_scorecard,
            _full_result(),
            True,
            scope=ScopeInfo(type_str="2 files"),
            surface_health=surfaces,
        )
        assert "Imported files" not in out  # kills L573 == -> !=

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_capabilities_shown_without_quality(self) -> None:
        # has_quality=False -> multi_surface is False -> capabilities line renders.
        # The `and -> or` mutation on multi_surface would flip it True and suppress
        # the capabilities line.
        surfaces = [
            SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=0, item_count=1),
            SurfaceHealth(name="Nested", score=7.0, file_count=1, finding_count=0, item_count=1),
        ]
        out = _capture(
            print_scorecard,
            _full_result(),
            False,
            scope=ScopeInfo(type_str="2 files"),
            surface_health=surfaces,
        )
        assert "capabilities" in out  # kills L564 and -> or
        # multi_surface is False here, so the surface bars must NOT render; the
        # `and -> or` mutation on the render gate would emit the "Main (1):" bar.
        assert "Main (1)" not in out  # kills L569 and -> or

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_capabilities_suppressed_when_multi_surface(self) -> None:
        # has_quality=True + 2 surfaces -> multi_surface True -> capabilities line
        # suppressed. `_render_scope(has_surface_health=multi_surface or has_items)`
        # with `or -> and` would recompute False and show the capabilities line.
        surfaces = [
            SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=0, item_count=1),
            SurfaceHealth(name="Nested", score=7.0, file_count=1, finding_count=0, item_count=1),
        ]
        out = _capture(
            print_scorecard,
            _full_result(),
            True,
            scope=ScopeInfo(type_str="2 files"),
            surface_health=surfaces,
        )
        assert "capabilities" not in out  # kills L567 or -> and

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_health_gated_off_without_quality(self) -> None:
        # has_quality=False -> both has_items (L565) and the elif gate (L575) are
        # False -> the item-health block must not render. Either `and -> or` mutation
        # flips has_items True / opens the elif, rendering the item rows. render_item_health
        # prints to item_scorecard's OWN console, so capture that one.
        from reporails_cli.formatters.text import item_scorecard

        items = [
            SurfaceHealth(name="itemalpha", score=8.0, file_count=1, finding_count=0, item_count=1),
            SurfaceHealth(name="itembeta", score=7.0, file_count=1, finding_count=0, item_count=1),
        ]
        with item_scorecard.console.capture() as icap:
            print_scorecard(
                _full_result(),
                False,
                scope=ScopeInfo(type_str="2 files"),
                surface_health=None,
                item_health=items,
            )
        assert "itemalpha" not in icap.get()  # kills L565 and L575 and -> or


class TestFreeTierCta:
    """The free-tier Pro-upsell line must not send a signed-in user to `ails auth login`."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_keyless_free_user_gets_the_login_cta(self, monkeypatch) -> None:
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: False)
        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="free", scope=ScopeInfo(type_str="2 files"))
        out = cap.get()
        assert "ails auth login" in out
        assert "reporails.com/account" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_keyed_free_user_gets_the_upgrade_cta(self, monkeypatch) -> None:
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="free", scope=ScopeInfo(type_str="2 files"))
        out = cap.get()
        assert "Upgrade to Pro" in out
        assert "reporails.com/account" in out
        assert "ails auth login" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_never_promises_a_fix_for_every_finding(self, monkeypatch) -> None:
        """The upgrade line may promise the remaining findings, the remedies for
        them, and an order to apply them — it must never claim a fix for
        EVERY finding (some Pro findings carry no remedy either)."""
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="free", scope=ScopeInfo(type_str="2 files"))
        out = cap.get().lower()
        assert "a fix for every finding" not in out
        assert "a remedy for every finding" not in out
        assert "pro adds the remedies" in out
        assert "the order to apply them" in " ".join(out.split())

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_free_line_replaces_not_joins_the_old_see_all_findings_cta(self, monkeypatch) -> None:
        """Exactly one upgrade line per run — the new Pro line, never the old
        'See all N findings' wording beside it."""
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="free", scope=ScopeInfo(type_str="2 files"))
        out = cap.get()
        assert "See all" not in out
        assert out.count("Upgrade to Pro") == 1


class TestProTierFixLocationLine:
    """The Pro terminal names where its fix text actually lives (JSON + MCP)."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pro_tier_gets_the_fix_location_line(self) -> None:
        from reporails_cli.formatters.text import scorecard

        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="Pro", scope=ScopeInfo(type_str="2 files"))
        out = cap.get()
        assert "--format json" in out
        assert "/reporails:ails heal" in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_free_tier_does_not_get_the_pro_fix_location_line(self, monkeypatch) -> None:
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
        with scorecard.console.capture() as cap:
            print_scorecard(_full_result(), True, tier="free", scope=ScopeInfo(type_str="2 files"))
        out = cap.get()
        assert "MCP tools" not in out


class TestSurfaceHealthWidth:
    """Two surfaces share a row only when both cells fit the terminal; otherwise one per row."""

    @staticmethod
    def _five() -> list[SurfaceHealth]:
        rows = [
            ("Main", 3.4, 1, 32, 0, 22, 10),
            ("Nested", 8.1, 2, 13, 2, 11, 2),
            ("Skills", 7.0, 15, 464, 33, 431, 15),
            ("Agents", 8.0, 14, 702, 28, 674, 14),
            ("Memory", 7.0, 29, 164, 87, 76, 12),
        ]
        return [
            SurfaceHealth(name=n, score=sc, file_count=fc, finding_count=fi, item_count=fc, errors=e)
            for n, sc, fc, fi, _m, _c, e in rows
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_narrow_terminal_renders_one_surface_per_line(self, monkeypatch) -> None:
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr(scorecard, "get_term_width", lambda: 96)
        with scorecard.console.capture() as cap:
            _render_surface_health(self._five())
        out = cap.get()
        lines = [ln for ln in out.splitlines() if ln.strip()]
        assert len(lines) == 5, out
        assert all(ln.count("):") == 1 for ln in lines), out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_wide_terminal_pairs_surfaces(self, monkeypatch) -> None:
        from reporails_cli.formatters.text import scorecard

        monkeypatch.setattr(scorecard, "get_term_width", lambda: 200)
        scorecard.console.width = 200
        try:
            with scorecard.console.capture() as cap:
                _render_surface_health(self._five())
        finally:
            scorecard.console.width = None
        out = cap.get()
        lines = [ln for ln in out.splitlines() if ln.strip()]
        assert len(lines) == 3, out
        assert lines[0].count("):") == 2, out


class TestRefusedRunTerminal:
    """A refused run prints the funnel CTA alone, never the tier lines beneath it."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pro_banner_with_payload_too_large_has_no_fix_location_line(self) -> None:
        from reporails_cli.core.platform.dto.diagnostics import FunnelError

        err = FunnelError(error="payload_too_large", tier="pro", status=413)
        out = _capture(print_scorecard, _Result(server_error=err), False, tier="Pro")
        assert "/reporails:ails heal" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    @pytest.mark.parametrize(
        ("error", "tier", "status"),
        [("rate_limit_exceeded", "free", 429), ("invalid_api_key", "anonymous", 401)],
    )
    def test_refused_free_run_has_no_second_upgrade_prompt(
        self, monkeypatch, error: str, tier: str, status: int
    ) -> None:
        from reporails_cli.core.platform.dto.diagnostics import FunnelError

        monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
        err = FunnelError(error=error, tier=tier, status=status)
        out = _capture(print_scorecard, _Result(server_error=err), False, tier="free")
        assert "Upgrade to Pro" not in out
        assert "Pro adds the remedies" not in out


class TestElementIdentity:
    @staticmethod
    def _skills(tmp_path, *folders):
        files = tuple(_FileRec(str(tmp_path / f / "SKILL.md"), "skills", str(tmp_path / f)) for f in folders) + tuple(
            _FileRec(str(tmp_path / f / "ref.md"), "skills", str(tmp_path / f)) for f in folders
        )
        return _Map(files)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_overlap_inside_one_skill_prints_no_headline(self, tmp_path) -> None:
        rmap = self._skills(tmp_path, ".claude/skills/foo")
        rows = (
            _Cross(
                "overlap", str(tmp_path / ".claude/skills/foo/SKILL.md"), str(tmp_path / ".claude/skills/foo/ref.md")
            ),
        )
        result = _Result(stats=_Stats(cross_file_overlaps=1), cross_file=rows)
        out = _capture(_render_cross_file_counts, result, tmp_path, element_namer(rmap, tmp_path))
        assert out == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_same_named_skills_are_two_elements_and_disambiguated(self, tmp_path) -> None:
        rmap = self._skills(tmp_path, ".claude/skills/foo", ".agents/skills/foo")
        rows = (
            _Cross(
                "overlap", str(tmp_path / ".claude/skills/foo/SKILL.md"), str(tmp_path / ".agents/skills/foo/SKILL.md")
            ),
        )
        result = _Result(stats=_Stats(cross_file_overlaps=1), cross_file=rows)
        out = _capture(_render_cross_file_counts, result, tmp_path, element_namer(rmap, tmp_path))
        assert out == (
            "1 element pair overlaps in topic \u2014 keep each topic in one file "
            "foo (skill, .agents/skills/foo) \u2194 foo (skill, .claude/skills/foo)"
        )


class TestSummaryLineShape:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_partners_cap_at_three_with_a_remainder_and_heads_pad(self, tmp_path) -> None:
        folders = ["a", "bb", "c", "d", "e", "f"]
        rmap = _Map(
            tuple(_FileRec(str(tmp_path / f"s/{f}/SKILL.md"), "skills", str(tmp_path / f"s/{f}")) for f in folders)
        )
        rows = tuple(
            _Cross("overlap", str(tmp_path / "s/a/SKILL.md"), str(tmp_path / f"s/{f}/SKILL.md")) for f in folders[1:]
        )
        result = _Result(stats=_Stats(cross_file_overlaps=5), cross_file=rows)
        with console.capture() as cap:
            _render_cross_file_counts(result, tmp_path, element_namer(rmap, tmp_path))
        assert cap.get().splitlines()[1] == "    a (skill) \u2194 bb, c, d, +2 more"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_summary_line_names_memory_files_by_stem_and_drops_the_kind_for_same_kind_partners(self, tmp_path) -> None:
        mem = [str(tmp_path / "memory" / n) for n in ("feedback_a.md", "feedback_b.md", "MEMORY.md")]
        rmap = _Map(tuple(_FileRec(m, "memory") for m in mem))
        rows = (_Cross("overlap", mem[0], mem[1]), _Cross("overlap", mem[0], mem[2]))
        result = _Result(stats=_Stats(cross_file_overlaps=2), cross_file=rows)
        out = _capture(_render_cross_file_counts, result, tmp_path, element_namer(rmap, tmp_path))
        assert out.endswith("MEMORY.md (memory index) \u2194 feedback_a (memory) feedback_a (memory) \u2194 feedback_b")

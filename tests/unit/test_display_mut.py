"""Mutation-killing behavioral tests for formatters/text/display.py.

Each test pins a branch, count, or threshold that a mutation probe found
uncovered — the assertion reddens the moment the injected bug returns. Cosmetic
display constants (whose exact text carries no behavioral contract) are left to
the equivalent-mutant bucket and not decorated here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from reporails_cli.core.mapper.skills import record_skills
from reporails_cli.core.platform.dto.diagnostics import (
    CrossFileFinding,
    FileAnalysis,
    QualityResult,
)
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap
from reporails_cli.core.platform.runtime.merger import (
    CombinedResult,
    CombinedStats,
    FindingItem,
)
from reporails_cli.formatters.text import display, file_groups
from reporails_cli.formatters.text.display import (
    _CardContext,
    _count_atoms,
    _detect_agent_name,
    _detect_tier,
    _filter_quality,
    _print_header,
    _render_cross_file_coordinates,
    _render_one_group,
    filter_result_to_paths,
    filter_ruleset_map_to_paths,
)
from reporails_cli.formatters.text.display_constants import get_sev_icons
from reporails_cli.formatters.text.file_groups import build_file_groups


def _rmap(*records: FileRecord, atoms: tuple[Atom, ...] = ()) -> RulesetMap:
    return RulesetMap(
        schema_version="1",
        embedding_model="",
        generated_at="2026-01-01T00:00:00Z",
        files=records,
        atoms=atoms,
    )


def _ratom(file_path: str) -> Atom:
    return Atom(
        line=1,
        text="x",
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="abstract",
        file_path=file_path,
    )


def _frec(path: str) -> FileRecord:
    return FileRecord(path=path, content_hash=f"sha256:{path}")


def _atom(charge: int, ambiguous: bool = False) -> SimpleNamespace:
    return SimpleNamespace(charge_value=charge, ambiguous=ambiguous)


# ── _count_atoms: directive / constraint / prose counts (L184) ────────


class TestCountAtoms:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_directive_charge_counted(self) -> None:
        # 3 directives (+1), 1 constraint (-1), 2 neutral (0). Two neutrals give the
        # constraint count asymmetry so `== -1 -> !=` (which would count the neutrals) is caught.
        atoms = [_atom(+1), _atom(+1), _atom(+1), _atom(-1), _atom(0), _atom(0)]
        scope = _count_atoms(atoms)
        assert scope.n_dir == 3  # kills L184 `charge_value == +1 -> !=` (would count -1 and neutrals)
        assert scope.n_con == 1  # kills L186 `charge_value == -1 -> !=` (would count the 2 neutrals -> 2)
        assert scope.n_atoms == 6
        assert scope.n_prose == 2  # 6 total - 3 dir - 1 con

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_ambiguous_counted(self) -> None:
        atoms = [_atom(+1, ambiguous=True), _atom(-1)]
        scope = _count_atoms(atoms)
        assert scope.n_amb == 1


# ── filter_result_to_paths: cross-file scoping + stat counts (L479/487/488) ──


def _cff(f1: str, f2: str, ftype: str) -> CrossFileFinding:
    return CrossFileFinding(file_1=f1, file_2=f2, line_1=1, line_2=1, finding_type=ftype)


class TestFilterResultCrossFile:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_cross_file_scope_and_stat_counts(self, tmp_path) -> None:
        a = tmp_path / "a.md"
        b = tmp_path / "b.md"
        z = tmp_path / "z.md"  # out of scope
        # cf_ab: both in scope; cf_az: only file_1 in scope (exercises the OR);
        # cf_rep: repetition in scope.
        cross = (
            _cff(str(a), str(b), "conflict"),
            _cff(str(a), str(z), "conflict"),
            _cff(str(a), str(b), "repetition"),
        )
        result = CombinedResult(findings=(), cross_file=cross, stats=CombinedStats())

        filtered = filter_result_to_paths(result, {a, b}, tmp_path)

        # All three have file_1=a in scope; with `or->and`, cf_az (file_2 out) is dropped.
        assert len(filtered.cross_file) == 3  # kills the `or -> and` scoping mutant
        # 1 repetition among the kept rows; a `== -> !=` would count the two
        # non-repetition rows instead.
        assert filtered.stats.cross_file_repetitions == 1

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_overlap_pair_count_follows_the_narrowed_rows(self, tmp_path) -> None:
        a, b, y, z = (tmp_path / n for n in ("a.md", "b.md", "y.md", "z.md"))
        cross = (
            _cff(str(a), str(b), "overlap"),
            _cff(str(b), str(a), "overlap"),  # same pair, other orientation
            _cff(str(y), str(z), "overlap"),  # out of scope
        )
        result = CombinedResult(findings=(), cross_file=cross, stats=CombinedStats(cross_file_overlaps=2))

        filtered = filter_result_to_paths(result, {a, b}, tmp_path)

        assert filtered.stats.cross_file_overlaps == 1


# ── _filter_quality: None guard + mean fallback (L512/L525) ────────────


class TestFilterQuality:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_none_quality_returns_none(self) -> None:
        # per_file carries a band so a mutated `is not None` branch would proceed
        # into dataclasses.replace(None, ...) and raise — either way the current
        # contract (return None) is what must hold.
        per_file = (FileAnalysis(file="a.md", display_score=8.0, stats={"atoms": 1}),)
        assert _filter_quality(None, per_file) is None  # kills L512 `is -> is not`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_mean_none_falls_back_to_aggregate_score(self) -> None:
        quality = QualityResult(display_score=7.0)
        # per_file has atoms (not filtered out) but no per-file display score, so the
        # mean is None and must fall back to the aggregate 7.0.
        per_file = (FileAnalysis(file="a.md", display_score=None, stats={"atoms": 2}),)
        out = _filter_quality(quality, per_file)
        assert out is not None
        assert out.display_score == 7.0  # kills L525 `is -> is not` (would keep None)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_all_unscored_subset_yields_none_when_aggregate_is_none(self) -> None:
        # Whole project has no scorable content: the api's own aggregate is `None`
        # (not a fabricated floor), and every file in the filtered subset is also
        # unscored. The mean-fallback chain must land on `None`, not raise, so the
        # text/json renderers can show "n/a" instead of crashing on `float(None)`.
        quality = QualityResult(display_score=None)
        per_file = (
            FileAnalysis(file="a.md", display_score=None, stats={"atoms": 2}),
            FileAnalysis(file="b.md", display_score=None, stats={"atoms": 2}),
        )
        out = _filter_quality(quality, per_file)
        assert out is not None
        assert out.display_score is None

        # The renderer must still succeed end-to-end on this filtered quality.
        from reporails_cli.formatters.text.scorecard import ScopeInfo, print_scorecard
        from reporails_cli.formatters.text.scorecard import console as scorecard_console

        combined = CombinedResult(
            quality=out,
            per_file_analysis=per_file,
            stats=CombinedStats(total_findings=0),
            offline=False,
        )
        with scorecard_console.capture() as cap:
            print_scorecard(combined, has_quality=True, scope=ScopeInfo(type_str="2 files"))
        assert "n/a" in cap.get()


# ── filter_ruleset_map_to_paths: None/empty guard + filtering (L534) ───


class TestFilterRulesetMap:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_filters_to_targeted_paths(self, tmp_path) -> None:
        # Build the real Pydantic RulesetMap (not a dataclass stub): the filter uses
        # model_copy, so a stub would false-green while production crashed.
        rm = _rmap(_frec("a.md"), _frec("b.md"), atoms=(_ratom("a.md"), _ratom("b.md")))
        out = filter_ruleset_map_to_paths(rm, {tmp_path / "a.md"}, tmp_path)
        assert [f.path for f in out.files] == ["a.md"]  # kills `is -> is not` (would skip filtering)
        assert [a.file_path for a in out.atoms] == ["a.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_empty_paths_returns_unchanged(self, tmp_path) -> None:
        rm = _rmap(_frec("a.md"), _frec("b.md"))
        out = filter_ruleset_map_to_paths(rm, set(), tmp_path)
        # `None or not paths` short-circuits on empty paths -> unchanged; `or->and`
        # would fall through and filter everything out.
        assert out is rm  # kills `or -> and`


# ── _render_one_group: card cap boundary (L97) ─────────────────────────


class TestRenderOneGroupCap:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_overflow_summary_at_cap(self, tmp_path) -> None:
        # 4 files, non-verbose cap is 3 -> the 4th collapses into a "... and 1 more" line.
        group_files = [
            (f"file{i}.md", [FindingItem(file=f"file{i}.md", line=1, severity="warning", rule="R", message="m")])
            for i in range(4)
        ]
        ctx = _CardContext(sev_icons=get_sev_icons(True), verbose=False, project_root=tmp_path)
        with display.console.capture() as cap:
            _render_one_group("file", group_files, ctx)
        out = cap.get()
        # At i >= 3 the overflow line renders; `>= -> >` would render all 4 cards, no summary.
        assert "and 1 more" in out  # kills L97 `>= -> >`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_overflow_under_cap(self, tmp_path) -> None:
        group_files = [
            (f"file{i}.md", [FindingItem(file=f"file{i}.md", line=1, severity="warning", rule="R", message="m")])
            for i in range(3)
        ]
        ctx = _CardContext(sev_icons=get_sev_icons(True), verbose=False, project_root=tmp_path)
        with display.console.capture() as cap:
            _render_one_group("file", group_files, ctx)
        assert "more" not in cap.get()


# ── _render_cross_file_coordinates: pluralization branch (L136) ────────


class TestCrossFileCoordinatesPlural:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_plural_suffix_when_count_not_one(self) -> None:
        coord = SimpleNamespace(count=2, file_1="a.md", file_2="b.md", finding_type="repetition")
        result = SimpleNamespace(cross_file_coordinates=(coord,))
        with display.console.capture() as cap:
            _render_cross_file_coordinates(result, get_sev_icons(True))
        # count=2 -> "repetitions"; `!= -> ==` drops the plural to "repetition".
        assert "repetitions" in cap.get()  # kills L136 `!= -> ==`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_singular_suffix_when_count_one(self) -> None:
        coord = SimpleNamespace(count=1, file_1="a.md", file_2="b.md", finding_type="repetition")
        result = SimpleNamespace(cross_file_coordinates=(coord,))
        with display.console.capture() as cap:
            _render_cross_file_coordinates(result, get_sev_icons(True))
        out = cap.get()
        assert "1 repetition" in out and "1 repetitions" not in out


# ── _render_detail_cta: held-key branch ───────────────────────────────


class TestDetailCta:
    """A signed-in user must not be told to sign in — that CTA is a dead end."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_keyless_user_gets_the_login_cta(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "reporails_cli.core.platform.adapters.api_client.has_api_key",
            lambda: False,
        )
        coord = SimpleNamespace(count=2, file_1="a.md", file_2="b.md", finding_type="repetition")
        result = SimpleNamespace(cross_file_coordinates=(coord,))
        with display.console.capture() as cap:
            _render_cross_file_coordinates(result, get_sev_icons(True))
        out = cap.get()
        assert "ails login" in out
        assert "reporails.com/account" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_keyed_user_gets_the_upgrade_cta(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "reporails_cli.core.platform.adapters.api_client.has_api_key",
            lambda: True,
        )
        coord = SimpleNamespace(count=2, file_1="a.md", file_2="b.md", finding_type="repetition")
        result = SimpleNamespace(cross_file_coordinates=(coord,))
        with display.console.capture() as cap:
            _render_cross_file_coordinates(result, get_sev_icons(True))
        out = cap.get()
        assert "Upgrade to Pro" in out
        assert "reporails.com/account" in out
        assert "ails login" not in out


# ── _print_header: tier badge branch (L332) ────────────────────────────


class TestPrintHeader:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pro_tier_shows_badge(self) -> None:
        with display.console.capture() as cap:
            _print_header("Pro")
        assert "Pro" in cap.get()  # kills L332 `!= -> ==` (would suppress the badge)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_free_tier_no_badge(self) -> None:
        with display.console.capture() as cap:
            _print_header("free")
        # free renders no tier badge; `and -> or` would render "free" as a badge.
        assert "free" not in cap.get()  # kills L332 `and -> or`


# ── _detect_tier: derives from the wire tier, never local credentials ──


class TestDetectTier:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pro_wire_tier_yields_pro(self) -> None:
        result = SimpleNamespace(offline=False, hints=(), tier="pro")
        assert _detect_tier(result, has_quality=True) == "Pro"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_team_wire_tier_yields_pro(self) -> None:
        result = SimpleNamespace(offline=False, hints=(), tier="team")
        assert _detect_tier(result, has_quality=True) == "Pro"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_free_wire_tier_yields_free(self) -> None:
        result = SimpleNamespace(offline=False, hints=(), tier="free")
        assert _detect_tier(result, has_quality=False) == "free"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_anonymous_wire_tier_yields_free(self) -> None:
        result = SimpleNamespace(offline=False, hints=(), tier="anonymous")
        assert _detect_tier(result, has_quality=False) == "free"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_offline_without_a_named_tier_yields_offline(self) -> None:
        result = SimpleNamespace(offline=True, hints=(), tier="")
        assert _detect_tier(result, has_quality=True) == "offline"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_wire_tier_falls_back_to_hints(self) -> None:
        """A result with no wire tier at all (e.g. pre-0.6.0 server) falls back
        to the hints/has_quality heuristic."""
        result = SimpleNamespace(offline=False, hints=({"x": 1},), tier="")
        assert _detect_tier(result, has_quality=False) == "free"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_wire_tier_falls_back_to_has_quality(self) -> None:
        result = SimpleNamespace(offline=False, hints=(), tier="")
        assert _detect_tier(result, has_quality=True) == "Pro"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_response_lacking_a_tier_but_carrying_quality_reads_as_pro(self) -> None:
        """The quality fallback has to stay REACHABLE.

        A paid response whose envelope omits `tier` must not read as free. The
        deserializer now forwards an empty tier for that case instead of inventing
        `free`, and an empty tier is exactly what routes here.
        """
        result = SimpleNamespace(offline=False, hints=(), tier="")
        assert _detect_tier(result, has_quality=True) == "Pro"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_unknown_non_empty_tier_reads_as_entitled(self) -> None:
        """A tier name this build does not know is entitled, not unentitled.

        Only the declared unentitled set downgrades the banner; a new paid plan the
        server ships before the client knows about it must not silently render as free.
        """
        result = SimpleNamespace(offline=False, hints=({"x": 1},), tier="enterprise")
        assert _detect_tier(result, has_quality=False) == "Pro"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_beta_credentials_file_never_influences_the_banner(self, monkeypatch) -> None:
        """A legacy `beta` credentials file must NOT influence the banner — only the
        wire tier does. `read_credentials` is monkeypatched to prove it is never
        consulted (and even if it were, `beta` is not a value the function accepts)."""
        import reporails_cli.core.platform.config.credentials as credentials

        monkeypatch.setattr(credentials, "read_credentials", lambda: {"tier": "beta"})
        result = SimpleNamespace(offline=False, hints=(), tier="anonymous")
        assert _detect_tier(result, has_quality=False) == "free"
        assert _detect_tier(result, has_quality=False) != "Pro (beta)"


# ── _detect_agent_name: non-generic agent selection (L199) ─────────────


class TestDetectAgentName:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_returns_most_common_non_generic_agent(self, tmp_path) -> None:
        rmap = _rmap(
            FileRecord(path="A.md", content_hash="sha256:a", agent="claude"),
            FileRecord(path="B.md", content_hash="sha256:b", agent="claude"),
            FileRecord(path="C.md", content_hash="sha256:c", agent="generic"),
        )
        # Current filters `agent != "generic"` -> claude; `!= -> ==` selects generic only.
        assert _detect_agent_name(rmap) == "claude"  # kills L199 `!= -> ==`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_two_distinctive_agents_join_both_names(self, tmp_path) -> None:
        """A union run: when two distinctive agents each run their own rules over their
        own files (per `stamp_file_agents`), the scorecard names every agent whose rules
        ran -- not just the most common one."""
        rmap = _rmap(
            FileRecord(path="CLAUDE.md", content_hash="sha256:a", agent="claude"),
            FileRecord(path=".cursorrules", content_hash="sha256:b", agent="cursor"),
        )
        assert _detect_agent_name(rmap) == "claude + cursor"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_map_names_the_agent_the_run_used(self) -> None:
        """An offline run with no model has no ruleset map; the agent whose rules ran is still named."""
        assert _detect_agent_name(None, ("claude",)) == "claude"
        assert _detect_agent_name(None, ("generic",)) == ""
        assert _detect_agent_name(None) == ""


# ── build_file_groups: root used for file-type routing (L241) ─────────


class TestBuildFileGroupsRoot:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_generic_routes_to_imported_using_project_root(self, tmp_path) -> None:
        abs_file = str(tmp_path / "x.md")
        finding = FindingItem(file=abs_file, line=1, severity="warning", rule="R", message="m")
        result = SimpleNamespace(findings=[finding])
        # file_type keyed by the project-root-relative path; only resolvable when the
        # normalization root is `project_root` (not cwd) -> routes into the "imported" group.
        ft_by_path = {"x.md": "generic"}
        groups = build_file_groups(result, ft_by_path, tmp_path)
        # `or -> and` makes root=cwd; the absolute path then normalizes off "x.md" and the
        # generic routing is lost, so the file lands outside "imported".
        assert "imported" in groups  # kills L241 `or -> and`
        assert abs_file in [fp for fp, _ in groups["imported"]]


# ── print_text_result: has_quality guard reached on no-findings path (L363) ──


class TestPrintTextResultHasQuality:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_none_quality_no_findings_renders_cleanly(self) -> None:
        # quality is None: current `is not None and bool(...)` short-circuits to False.
        # `and -> or` would evaluate None.display_score and raise AttributeError.
        result = CombinedResult(findings=(), quality=None)
        with display.console.capture() as cap:
            display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=False)
        assert "No findings" in cap.get()  # kills L363 `and -> or`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_findings_render_reaches_scorecard(self, tmp_path) -> None:
        # A finding drives the full findings+scorecard path. quality is None, so the
        # `and -> or` mutation on has_quality (L401) evaluates bool(None.compliance_band)
        # and raises; the scan root (L361) also flows into finding grouping here.
        finding = FindingItem(
            file=str(tmp_path / "CLAUDE.md"), line=2, severity="error", rule="CORE:S:0001", message="broken"
        )
        result = CombinedResult(findings=(finding,), quality=None)
        with display.console.capture() as cap:
            display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=False, project_root=tmp_path)
        out = cap.get()
        # The file-group block renders only after _render_findings_and_scorecard passes the
        # L401 has_quality guard; `and -> or` there evaluates bool(None.compliance_band) and
        # raises first, so no group header/footer would reach the console.
        assert "1 findings" in out  # kills L401 `and -> or`

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_generic_file_type_routes_to_imported_group(self, tmp_path) -> None:
        # A generic-classified file routes into the "Imported" group. That routing needs
        # both the scan root (L361: project_root, not cwd) to normalize the finding key AND
        # the file_type_by_path map to reach build_file_groups intact (L374: the map, not {}).
        abs_file = str(tmp_path / "x.md")
        finding = FindingItem(file=abs_file, line=1, severity="warning", rule="R", message="m")
        result = CombinedResult(findings=(finding,), quality=None)
        with display.console.capture() as cap:
            display.print_text_result(
                result,
                elapsed_ms=0,
                ascii_mode=True,
                verbose=False,
                project_root=tmp_path,
                file_type_by_path={"x.md": "generic"},
            )
        out = cap.get()
        # `or -> and` at L361 makes root=cwd (key mismatch); `or -> and` at L374 passes {}
        # (routing lost). Either drops the file out of the Imported group.
        assert "Imported" in out  # kills L361 `or -> and` and L374 `or -> and`


# ── _render_findings_and_scorecard: item-health gating (L423) ──────────


class TestItemHealthGating:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_single_surface_multifile_renders_per_item_bars(self, tmp_path) -> None:
        # Two skills -> exactly ONE surface ("skill") whose item_count is 2. That is
        # the `len(surfaces) == 1 and surfaces[0].item_count > 1` case: item-health bars
        # (one per skill) render. `== -> !=` makes the guard False -> item_health None ->
        # no per-item bars.
        from reporails_cli.formatters.text import item_scorecard
        from reporails_cli.formatters.text.scorecard import ScopeInfo

        rmap = _rmap(
            FileRecord(path=".claude/skills/alpha/SKILL.md", content_hash="sha256:a", type="skills", agent="claude"),
            FileRecord(path=".claude/skills/beta/SKILL.md", content_hash="sha256:b", type="skills", agent="claude"),
        )
        record_skills(rmap, ["claude"], tmp_path)
        per_file = (
            FileAnalysis(file=".claude/skills/alpha/SKILL.md", display_score=8.0, stats={"atoms": 5}),
            FileAnalysis(file=".claude/skills/beta/SKILL.md", display_score=4.0, stats={"atoms": 5}),
        )
        quality = QualityResult(display_score=6.0)
        result = CombinedResult(findings=(), quality=quality, per_file_analysis=per_file)

        with item_scorecard.console.capture() as cap:
            display._render_findings_and_scorecard(result, rmap, True, False, ScopeInfo(), "free", 0, tmp_path, {})
        out = cap.get()
        # Both per-item rows render only when item_health is computed (the guard holds).
        assert "alpha" in out and "beta" in out  # kills L423 `== -> !=`


class TestElementNamerBuiltOnce:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_one_namer_serves_every_file_card(self, monkeypatch, tmp_path) -> None:
        calls: list[object] = []
        real = display.element_namer
        monkeypatch.setattr(display, "element_namer", lambda *a: calls.append(a) or real(*a))
        msg = "40% of the instructions in this file and `B.md` cover the same topics \u2014 the copies can drift apart."
        findings = tuple(
            FindingItem(file=str(tmp_path / name), line=3, severity="warning", rule="CORE:C:0044", message=msg)
            for name in ("A.md", "C.md", "D.md")
        )
        result = CombinedResult(findings=findings, quality=None)
        with display.console.capture():
            display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=True, project_root=tmp_path)
        assert len(calls) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_namer_when_nothing_names_an_element(self, monkeypatch, tmp_path) -> None:
        calls: list[object] = []
        monkeypatch.setattr(display, "element_namer", lambda *a: calls.append(a))
        finding = FindingItem(file=str(tmp_path / "A.md"), line=3, severity="warning", rule="R", message="m")
        with display.console.capture():
            display.print_text_result(
                CombinedResult(findings=(finding,), quality=None),
                elapsed_ms=0,
                ascii_mode=True,
                verbose=False,
                project_root=tmp_path,
            )
        assert calls == []


# ── Alias files render as one card, the header states the scanned count, the Cross-file list is capped ──


def _finding(path: str, line: int = 1, rule: str = "CORE:C:0042", message: str = "Vague") -> FindingItem:
    return FindingItem(file=path, line=line, severity="warning", rule=rule, message=message)


class TestAliasFilesRenderOneCard:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_identical_agents_and_claude_files_share_one_card(self, tmp_path, capsys) -> None:
        (tmp_path / "AGENTS.md").write_text("# Proj\n\nRun `uv run pytest` before committing.\n")
        (tmp_path / "CLAUDE.md").write_text("# Proj\n\nRun `uv run pytest` before committing.\n")
        shared = {"line": 3, "rule": "CORE:C:0042", "message": "Vague"}
        result = CombinedResult(
            findings=(
                _finding("AGENTS.md", **shared),
                _finding("CLAUDE.md", **shared),
                _finding("CLAUDE.md", line=1, rule="CLAUDE:S:0012", message="No frontmatter block found"),
            ),
            quality=None,
        )
        display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=False, project_root=tmp_path)
        out = capsys.readouterr().out
        assert "AGENTS.md (+CLAUDE.md)" in out
        # One card: the alias has no card of its own, and its footer counts the findings rendered.
        assert out.count("CLAUDE.md") == 1
        assert "2 findings" in out
        # The finding only CLAUDE.md carried still shows, on the shared card.
        assert "No frontmatter block found" in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_alias_hints_fold_into_the_canonical_card_once(self, tmp_path) -> None:
        from reporails_cli.core.platform.dto.diagnostics import Hint

        hint = {"diagnostic_type": "CORE:C:0044", "count": 1, "severity": "warning", "warning_count": 1}
        hints = [Hint(file="AGENTS.md", **hint), Hint(file="CLAUDE.md", **hint)]
        folded = file_groups.build_hints_by_file(hints, tmp_path, {"AGENTS.md": ["CLAUDE.md"]})
        assert list(folded) == ["AGENTS.md"]
        assert len(folded["AGENTS.md"]) == 1


class TestGroupHeaderStatesScannedCount:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_header_matches_the_summary_surface_row(self, tmp_path, capsys) -> None:
        # Three rule files scanned, one with a finding; a Main file keeps a second surface so the Summary rows render.
        rmap = _rmap(
            _frec("CLAUDE.md"),
            _frec(".claude/rules/a.md"),
            _frec(".claude/rules/b.md"),
            _frec(".claude/rules/c.md"),
        )
        result = CombinedResult(
            findings=(_finding(".claude/rules/a.md"), _finding("CLAUDE.md")), quality=QualityResult()
        )
        display.print_text_result(
            result, elapsed_ms=0, ascii_mode=True, verbose=False, ruleset_map=rmap, project_root=tmp_path
        )
        out = capsys.readouterr().out
        assert "Rules (3):" in out  # the Summary surface row
        assert "Rules (3)" in out.split("Summary")[0]  # the card group header says the same

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_header_without_scanned_set_counts_files_with_findings(self, tmp_path) -> None:
        group = [("a.md", [_finding("a.md")]), ("b.md", [_finding("b.md")])]
        with display.console.capture() as cap:
            display._render_group_header("file", group, None, tmp_path)
        assert "(2)" in cap.get()


class TestCrossFileListIsCapped:
    @staticmethod
    def _result(n: int) -> SimpleNamespace:
        coords = tuple(
            SimpleNamespace(count=i + 1, file_1=f"a{i}.md", file_2=f"b{i}.md", finding_type="overlap") for i in range(n)
        )
        return SimpleNamespace(cross_file_coordinates=coords)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_names_the_highest_counts_and_counts_the_rest(self) -> None:
        with display.console.capture() as cap:
            _render_cross_file_coordinates(self._result(6), get_sev_icons(True))
        out = cap.get()
        assert out.count("↔") == 3
        assert "a5.md" in out and "a4.md" in out and "a3.md" in out  # counts 6, 5, 4
        assert "a0.md" not in out
        assert "+3 more pairs" in out
        assert "ails check -v" in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_verbose_names_every_pair(self) -> None:
        with display.console.capture() as cap:
            _render_cross_file_coordinates(self._result(6), get_sev_icons(True), verbose=True)
        out = cap.get()
        assert out.count("↔") == 6
        assert "more pair" not in out

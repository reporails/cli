"""Unit tests for the wire payload module."""

from __future__ import annotations

from pathlib import Path

import msgpack
import pytest

from reporails_cli.core.cache.map_cache import atoms_to_dicts, dicts_to_atoms
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map
from reporails_cli.core.platform.adapters.payload import (
    WIRE_SCHEMA_VERSION,
    encode_msgpack,
    project_local,
    project_payload,
)
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import (
    Atom,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)

_ROOT = Path("/tmp/reporails-test-root")


def _atom(idx: int, charge: int = 1, has_emb: bool = True) -> Atom:
    return Atom(
        line=idx,
        text="",
        plain_text="",
        kind="excitation",
        charge="DIRECTIVE" if charge > 0 else "CONSTRAINT" if charge < 0 else "NEUTRAL",
        charge_value=charge,
        modality="imperative",
        specificity="named",
        scope_conditional=False,
        format="prose",
        named_tokens=("foo",) if charge else (),
        italic_tokens=("never",) if charge < 0 else (),
        bold_tokens=(),
        unformatted_code=(),
        position_index=idx % 10,
        token_count=8,
        file_path="CLAUDE.md",
        embedding_int8=tuple(((i + idx) % 256) - 128 for i in range(384)) if has_emb else None,
        heading_context="A" * 200,
        depth=2,
        ambiguous=False,
        embedded_charge_markers=(),
    )


def _ruleset(n_atoms: int = 10, n_files: int = 1) -> RulesetMap:
    files = tuple(
        FileRecord(
            path=f"f{i}/CLAUDE.md",
            content_hash="sha256:" + "a" * 64,
            loading="session_start",
            scope="global",
            agent="claude",
            description="desc",
            description_embedding=tuple((j % 256) - 128 for j in range(384)),
        )
        for i in range(n_files)
    )
    atoms = tuple(_atom(i, (i % 3) - 1) for i in range(n_atoms))
    return RulesetMap(
        schema_version="2",
        embedding_model="test-embedder",
        generated_at="2026-05-06T00:00:00+00:00",
        files=files,
        atoms=atoms,
        summary=RulesetSummary(
            n_atoms=n_atoms,
            n_charged=n_atoms // 2,
            n_neutral=n_atoms // 2,
        ),
    )


class TestProjectionShape:
    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_text_fields_dropped(self) -> None:
        rm = _ruleset(n_atoms=2)
        proj = project_payload(rm, _ROOT)
        for atom in proj["atoms"]:
            assert "text" not in atom
            assert "plain_text" not in atom
            assert "heading_context" not in atom
            assert "hc" not in atom

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_no_cluster_fields_on_wire(self) -> None:
        # Clustering is retired: the wire ships no per-atom cluster id (`k`) and
        # no clusters block.
        rm = _ruleset(n_atoms=3)
        proj = project_payload(rm, _ROOT)
        assert "clusters" not in proj
        for atom in proj["atoms"]:
            assert "k" not in atom

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_inline_tokens_become_counts(self) -> None:
        rm = _ruleset(n_atoms=3)
        proj = project_payload(rm, _ROOT)
        for atom in proj["atoms"]:
            assert "il" not in atom
            assert isinstance(atom.get("nb"), int)
            assert isinstance(atom.get("ib"), int)
            assert isinstance(atom.get("bb"), int)
            assert isinstance(atom.get("ub"), int)

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_inline_counts_match_source(self) -> None:
        rm = _ruleset(n_atoms=4)
        proj = project_payload(rm, _ROOT)
        for src, atom in zip(rm.atoms, proj["atoms"], strict=True):
            assert atom["nb"] == len(src.named_tokens)
            assert atom["ib"] == len(src.italic_tokens)
            assert atom["bb"] == len(src.bold_tokens)
            assert atom["ub"] == len(src.unformatted_code)

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_per_atom_embedding_ships(self) -> None:
        # The per-atom int8 topic vector rides the wire as `e` (unsigned bytes,
        # one per dim — 384). Prototype cosine (`ps`) is not projected.
        rm = _ruleset(n_atoms=1)
        proj = project_payload(rm, _ROOT)
        assert isinstance(proj["atoms"][0]["e"], bytes)
        assert len(proj["atoms"][0]["e"]) == 384
        assert "ps" not in proj["atoms"][0]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    @pytest.mark.parametrize("empty", [None, ()])
    def test_atom_without_embedding_omits_e(self, empty: object) -> None:
        # A heading-style atom carrying no embedding (None) — or an empty vector —
        # ships no `e` field, so the projected key and the size estimate agree.
        rm = _ruleset(n_atoms=1)
        rm.atoms[0].embedding_int8 = empty  # type: ignore[assignment]
        proj = project_payload(rm, _ROOT)
        assert "e" not in proj["atoms"][0]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_schema_version_is_the_current_wire_version(self) -> None:
        rm = _ruleset()
        proj = project_payload(rm, _ROOT)
        assert proj["schema_version"] == str(WIRE_SCHEMA_VERSION)


class TestNegativeSectionKey:
    """`ns` marks a bare negative heading and the list items directly under one."""

    @staticmethod
    def _projected(*specs: tuple[str, str, str, str]) -> list[dict]:
        rm = _ruleset(0)
        atoms = tuple(
            Atom(
                line=i + 1,
                text=text,
                kind=kind,
                charge="CONSTRAINT",
                charge_value=-1,
                modality="imperative",
                specificity="abstract",
                format=fmt,
                heading_context=ctx,
                file_path="CLAUDE.md",
            )
            for i, (kind, fmt, text, ctx) in enumerate(specs)
        )
        rm.atoms = atoms
        return project_payload(rm, _ROOT)["atoms"]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_heading_and_its_list_items_carry_ns(self) -> None:
        atoms = self._projected(
            ("heading", "heading", "Don'ts", ""),
            ("excitation", "list", "Use mock objects in tests.", "Don'ts"),
            ("excitation", "numbered", "Skip the linter.", "Don'ts"),
        )
        assert [a.get("ns") for a in atoms] == [True, True, True]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_other_atoms_carry_no_ns(self) -> None:
        atoms = self._projected(
            ("excitation", "prose", "Use mock objects in tests.", "Don'ts"),
            ("excitation", "list", "Use real objects.", "Testing"),
            ("heading", "heading", "Never Push Directly to Main", ""),
            ("heading", "heading", "Testing", ""),
        )
        assert all("ns" not in a for a in atoms)


class TestWirePayloadPrivacy:
    """The frontmatter `description` prose never crosses the wire, and file / local-file
    paths ride relative to the scan root rather than as absolute local filesystem paths
    that disclose the user's directory layout."""

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_description_never_crosses_the_wire(self) -> None:
        rm = _ruleset(n_atoms=1, n_files=2)
        proj = project_payload(rm, _ROOT)
        assert proj["files"], "fixture produced no file records"
        for fd in proj["files"]:
            assert "description" not in fd
            # Only the embedding ships.
            assert "de" in fd

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_file_paths_are_scan_root_relative(self) -> None:
        files = tuple(
            FileRecord(
                path=p,
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="global",
                agent="claude",
                description="Secret internal codename PROJECT-FALCON",
                description_embedding=(1,) * 384,
            )
            for p in (
                "/home/user/project/CLAUDE.md",
                "/home/user/project/.claude/agents/foo.md",
                "/home/user/project/tests/CLAUDE.md",
            )
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        proj = project_payload(rm, Path("/home/user/project"))
        paths = [fd["path"] for fd in proj["files"]]
        assert paths == ["CLAUDE.md", ".claude/agents/foo.md", "tests/CLAUDE.md"]
        for p in paths:
            assert not p.startswith("/")
            assert not p.startswith("~")

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_single_mapped_file_is_still_scan_root_relative(self) -> None:
        # A project with a single `CLAUDE.md`: the file is still keyed relative to the scan root,
        # never by its absolute path.
        files = (
            FileRecord(
                path="/home/user/project/CLAUDE.md",
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="global",
                agent="claude",
            ),
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        proj = project_payload(rm, Path("/home/user/project"))
        assert proj["files"][0]["path"] == "CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_rules_only_project_files_are_relative_to_the_real_project_root(self) -> None:
        # A `.claude/rules/`-only project — every mapped file sits under `.claude/rules/`,
        # so a root guessed from the mapped files' own common ancestor lands one directory
        # too deep (`.claude/rules`, not the project root) and the response can't map back.
        files = tuple(
            FileRecord(
                path=p,
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="global",
                agent="claude",
            )
            for p in (
                "/home/user/project/.claude/rules/a.md",
                "/home/user/project/.claude/rules/b.md",
            )
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        proj = project_payload(rm, Path("/home/user/project"))
        paths = [fd["path"] for fd in proj["files"]]
        assert paths == [".claude/rules/a.md", ".claude/rules/b.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_file_outside_project_root_but_under_home_carries_no_username(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A user-level `~/.claude/CLAUDE.md` (outside the project root entirely) rides
        # the wire under a `~/`-prefixed key — never the home directory, never the username.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/user")))
        files = (
            FileRecord(
                path="/home/user/.claude/CLAUDE.md",
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="user",
                agent="claude",
            ),
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        proj = project_payload(rm, Path("/home/user/project"))
        path = proj["files"][0]["path"]
        assert path == "~/.claude/CLAUDE.md"
        assert "user" not in path  # the literal `~` stands in for the home directory, never the username
        assert not path.startswith("/")

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_local_files_are_relative_and_reuse_a_mapped_files_index(self) -> None:
        files = tuple(
            FileRecord(
                path=p,
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="global",
                agent="claude",
            )
            for p in (
                "/home/user/project/CLAUDE.md",
                "/home/user/project/.claude/agents/foo.md",
            )
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        root = Path("/home/user/project")
        mapped = [fd["path"] for fd in project_payload(rm, root)["files"]]
        local = [
            LocalEntry(
                rule="CORE:G:0005",
                file="/home/user/project/.claude/agents/foo.md",
                line=3,
                severity="error",
            ),
            LocalEntry(
                rule="CORE:S:0030",
                file="/home/user/project/.claude/settings.json",
                line=0,
                severity="warning",
            ),
        ]
        fields = project_local(local, mapped, root)
        # Names an already-mapped file: reuses that file's index rather than a fresh
        # local_files slot — the two must stay one file, not become two.
        assert fields["local"][0]["f"] == 1
        # Names a file outside the mapped set: gets a new slot, sent relative rather
        # than as an absolute local path.
        assert fields["local_files"] == [".claude/settings.json"]
        assert fields["local"][1]["f"] == len(mapped)
        for p in fields["local_files"]:
            assert not p.startswith("/")
            assert not p.startswith("~")

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_local_finding_matches_the_mapped_file_by_exact_path_not_by_suffix(self) -> None:
        # A local finding on `<root>/tests/CLAUDE.md` must attribute to the mapped
        # `tests/CLAUDE.md` entry, never to the mapped root `CLAUDE.md` — the old suffix
        # match picked the first mapped path `tests/CLAUDE.md` ends with, which is the
        # root file, since `tests/CLAUDE.md` also ends with `/CLAUDE.md`.
        root = Path("/home/user/project")
        files = tuple(
            FileRecord(
                path=p,
                content_hash="sha256:" + "a" * 64,
                loading="session_start",
                scope="global",
                agent="claude",
            )
            for p in ("/home/user/project/CLAUDE.md", "/home/user/project/tests/CLAUDE.md")
        )
        rm = RulesetMap(
            schema_version="2",
            embedding_model="test-embedder",
            generated_at="2026-05-06T00:00:00+00:00",
            files=files,
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        mapped = [fd["path"] for fd in project_payload(rm, root)["files"]]
        assert mapped == ["CLAUDE.md", "tests/CLAUDE.md"]
        local = [
            LocalEntry(
                rule="CORE:G:0005",
                file="/home/user/project/tests/CLAUDE.md",
                line=3,
                severity="error",
            ),
        ]
        fields = project_local(local, mapped, root)
        assert fields["local"][0]["f"] == 1  # `tests/CLAUDE.md`, never index 0 (`CLAUDE.md`)
        assert "local_files" not in fields  # the file is already mapped — no new slot


class TestSerializeRoundTrip:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_atoms_survive_json_round_trip(self, tmp_path: Path) -> None:
        rm = _ruleset(n_atoms=4)
        path = tmp_path / "map.json"
        save_ruleset_map(rm, path)
        loaded = load_ruleset_map(path)
        assert len(loaded.atoms) == len(rm.atoms)
        assert loaded.summary.n_atoms == rm.summary.n_atoms


class TestEncoding:
    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_leading_version_byte(self) -> None:
        rm = _ruleset(n_atoms=1)
        encoded = encode_msgpack(project_payload(rm, _ROOT))
        assert encoded[0] == 5
        assert encoded[0] == WIRE_SCHEMA_VERSION

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_round_trip_decode(self) -> None:
        rm = _ruleset(n_atoms=2, n_files=1)
        proj = project_payload(rm, _ROOT)
        encoded = encode_msgpack(proj)
        decoded = msgpack.unpackb(encoded[1:], raw=False)
        assert decoded["schema_version"] == "5"
        assert decoded["schema_version"] == str(encoded[0]) == str(WIRE_SCHEMA_VERSION)
        assert len(decoded["atoms"]) == len(proj["atoms"])
        assert len(decoded["files"]) == len(proj["files"])
        assert decoded["atoms"][0].keys() == proj["atoms"][0].keys()


class TestRootHasNoCwdFallback:
    """`project_payload`/`project_local` never fall back to `Path.cwd()` — a caller that
    forgets `root` gets a loud `TypeError`, not a silent wrong-root payload."""

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_project_payload_root_is_a_required_argument(self) -> None:
        import inspect

        sig = inspect.signature(project_payload)
        assert sig.parameters["root"].default is inspect.Parameter.empty

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_project_local_root_is_a_required_argument(self) -> None:
        import inspect

        sig = inspect.signature(project_local)
        assert sig.parameters["root"].default is inspect.Parameter.empty

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_project_payload_without_root_raises(self) -> None:
        rm = _ruleset(n_atoms=1)
        with pytest.raises(TypeError):
            project_payload(rm)  # type: ignore[call-arg]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_project_local_without_root_raises(self) -> None:
        with pytest.raises(TypeError):
            project_local([], ["CLAUDE.md"])  # type: ignore[call-arg]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_the_no_root_convenience_wrapper_is_gone(self) -> None:
        """The unused `serialize()` convenience (`project_payload` with no root) had no
        caller anywhere — removed rather than given a root it would have to guess."""
        import reporails_cli.core.platform.adapters.payload as payload_module

        assert not hasattr(payload_module, "serialize")


class TestLeadInKey:
    """`li` marks a line ending with a colon that introduces the list, code block or table after it."""

    @staticmethod
    def _projected(markdown: str) -> list[tuple[str, bool]]:
        """Each projected atom's text and whether it carries `li`, for real markdown through the parse."""
        atoms = tokenize(markdown)
        for a in atoms:
            a.file_path = "CLAUDE.md"
        rm = _ruleset(0)
        rm.atoms = tuple(atoms)
        wire = project_payload(rm, _ROOT)["atoms"]
        return [(a.text, bool(w.get("li"))) for a, w in zip(atoms, wire, strict=True)]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    @pytest.mark.parametrize(
        "markdown",
        [
            "Follow these rules:\n\n- alpha rule\n- bravo rule",
            "Follow these rules:\n\n1. alpha rule\n2. bravo rule",
            "Follow these rules:\n- alpha rule\n- bravo rule",
            "Follow these rules:\n\n```\nmake build\n```",
            "Follow these rules:\n\n    make build",
            "Follow these rules:\n\n| Rule | Why |\n| --- | --- |\n| alpha | because |",
            "**Follow these rules:**\n\n- alpha rule\n- bravo rule",
            "1. Create the file:\n\n```\nmake build\n```",
        ],
    )
    def test_a_colon_line_above_a_list_code_block_or_table_carries_li(self, markdown: str) -> None:
        assert self._projected(markdown)[0][1] is True

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_a_lead_in_above_a_list_of_items_too_short_to_be_atoms_still_carries_li(self) -> None:
        """Items under five characters are dropped, so no atom follows the lead-in; the markdown still does."""
        assert self._projected("Run these:\n\n- a\n- b") == [("Run these:", True)]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    @pytest.mark.parametrize(
        "markdown",
        [
            "Follow these rules:\n\nKeep functions short.",
            "Follow these rules\n\n- alpha rule\n- bravo rule",
            "Follow these rules.\n\n- alpha rule\n- bravo rule",
            "# Follow these rules:\n\n- alpha rule\n- bravo rule",
            "Follow these rules:\n\n> a quoted note here",
            "- Follow these rules:\n- Keep functions short.",
            "Follow these rules:\na. alpha rule\nb. bravo rule",
        ],
    )
    def test_a_line_without_a_colon_or_without_a_block_after_it_carries_no_li(self, markdown: str) -> None:
        assert not any(li for _, li in self._projected(markdown))

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_only_the_last_line_of_the_paragraph_can_be_the_lead_in(self) -> None:
        got = self._projected("Setup notes here:\nRun these:\n\n- alpha rule\n- bravo rule")
        assert got == [("Setup notes here:", False), ("Run these:", True), ("alpha rule", False), ("bravo rule", False)]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_a_list_item_that_introduces_a_nested_list_carries_li(self) -> None:
        got = self._projected("- Run these steps:\n  - alpha step\n  - bravo step\n- Then stop here")
        assert [li for _, li in got] == [True, False, False, False]

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_a_lead_in_survives_the_map_and_atom_cache_round_trips(self, tmp_path: Path) -> None:
        atoms = tokenize("Run these:\n\n- alpha\n- bravo")
        rm = _ruleset(0)
        rm.atoms = tuple(atoms)
        save_ruleset_map(rm, tmp_path / "map.json")
        assert [a.lead_in for a in load_ruleset_map(tmp_path / "map.json").atoms] == [True, False, False]
        assert [a.lead_in for a in dicts_to_atoms(atoms_to_dicts(atoms))] == [True, False, False]

"""Unit tests for the wire payload module."""

from __future__ import annotations

import json

import msgpack
import pytest

from reporails_cli.core.api_client import _strip_and_serialize
from reporails_cli.core.mapper.mapper import (
    Atom,
    ClusterRecord,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)
from reporails_cli.core.payload import (
    WIRE_SCHEMA_VERSION_V3,
    encode_msgpack,
    project_payload,
)


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
        cluster_id=idx % 5,
        embedding_int8=tuple(((i + idx) % 256) - 128 for i in range(384)) if has_emb else None,
        heading_context="A" * 200,
        depth=2,
        ambiguous=False,
        embedded_charge_markers=(),
    )


def _ruleset(n_atoms: int = 10, n_files: int = 1, n_clusters: int = 3) -> RulesetMap:
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
    clusters = tuple(
        ClusterRecord(
            id=i, n_atoms=4, n_charged=2, n_neutral=2, centroid=tuple(((i * 7 + j) % 1000) / 1000.0 for j in range(384))
        )
        for i in range(n_clusters)
    )
    return RulesetMap(
        schema_version="2",
        embedding_model="all-MiniLM-L6-v2",
        generated_at="2026-05-06T00:00:00+00:00",
        files=files,
        atoms=atoms,
        clusters=clusters,
        summary=RulesetSummary(
            n_atoms=n_atoms,
            n_charged=n_atoms // 2,
            n_neutral=n_atoms // 2,
            n_topics=n_clusters,
            n_topics_charged=n_clusters // 2,
        ),
    )


class TestProjectionShape:
    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_text_fields_dropped(self) -> None:
        rm = _ruleset(n_atoms=2)
        proj = project_payload(rm)
        for atom in proj["atoms"]:
            assert "text" not in atom
            assert "plain_text" not in atom
            assert "heading_context" not in atom
            assert "hc" not in atom

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_inline_tokens_become_counts(self) -> None:
        rm = _ruleset(n_atoms=3)
        proj = project_payload(rm)
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
        proj = project_payload(rm)
        for src, atom in zip(rm.atoms, proj["atoms"], strict=True):
            assert atom["nb"] == len(src.named_tokens)
            assert atom["ib"] == len(src.italic_tokens)
            assert atom["bb"] == len(src.bold_tokens)
            assert atom["ub"] == len(src.unformatted_code)

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_cluster_centroids_dropped(self) -> None:
        rm = _ruleset(n_clusters=5)
        proj = project_payload(rm)
        for cluster in proj["clusters"]:
            assert "centroid" not in cluster
            assert "centroid_b64" not in cluster
            assert "ce" not in cluster

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_embedding_packed_as_bytes(self) -> None:
        rm = _ruleset(n_atoms=1)
        proj = project_payload(rm)
        atom = proj["atoms"][0]
        assert isinstance(atom["e"], bytes)
        assert len(atom["e"]) == 384

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_schema_version_is_3(self) -> None:
        rm = _ruleset()
        proj = project_payload(rm)
        assert proj["schema_version"] == "3"


class TestEncoding:
    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_leading_version_byte(self) -> None:
        rm = _ruleset(n_atoms=1)
        encoded = encode_msgpack(project_payload(rm))
        assert encoded[0] == WIRE_SCHEMA_VERSION_V3 == 3

    @pytest.mark.unit
    @pytest.mark.subsys_server
    def test_round_trip_decode(self) -> None:
        rm = _ruleset(n_atoms=2, n_files=1, n_clusters=1)
        proj = project_payload(rm)
        encoded = encode_msgpack(proj)
        decoded = msgpack.unpackb(encoded[1:], raw=False)
        assert decoded["schema_version"] == "3"
        assert len(decoded["atoms"]) == len(proj["atoms"])
        assert len(decoded["files"]) == len(proj["files"])
        assert decoded["atoms"][0]["e"] == proj["atoms"][0]["e"]


class TestShrinkage:
    @pytest.mark.unit
    @pytest.mark.subsys_server
    @pytest.mark.parametrize(
        "n_atoms,n_files,n_clusters,min_shrink",
        [
            (50, 5, 10, 1.5),
            (200, 10, 30, 1.5),
            (1000, 30, 100, 1.5),
        ],
    )
    def test_smaller_than_legacy(self, n_atoms: int, n_files: int, n_clusters: int, min_shrink: float) -> None:
        rm = _ruleset(n_atoms=n_atoms, n_files=n_files, n_clusters=n_clusters)
        legacy_bytes = len(json.dumps(_strip_and_serialize(rm)).encode("utf-8"))
        new_bytes = len(encode_msgpack(project_payload(rm)))
        assert new_bytes < legacy_bytes
        assert legacy_bytes / new_bytes >= min_shrink

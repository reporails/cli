"""Regression guard for `cluster_topics` — the mapper's grouping stage.

The resulting `cluster_id` partition is load-bearing for downstream grouping
and scoring, so the *partition* must stay stable. These tests pin the
behaviors of the current grouping (distinct groups stay distinct, a chain of
near-neighbors does not all collapse into one group, headings are excluded,
small inputs fall back cleanly). A change to the grouping method that would
scramble those assignments trips these tests before it can ship a silent
scoring drift.
"""

from __future__ import annotations

import math

import pytest

from reporails_cli.core.mapper.cluster import cluster_topics
from reporails_cli.core.platform.dto.ruleset import Atom

_DIM = 384


def _atom(vec: list[float], *, kind: str = "excitation", charge_value: int = 1) -> Atom:
    """Build an atom whose int8 embedding points along `vec` (L2-normalized downstream)."""
    quant = tuple(int(max(-127, min(127, round(x * 100)))) for x in vec)
    return Atom(
        line=1,
        text="t",
        kind=kind,
        charge="DIRECTIVE",
        charge_value=charge_value,
        modality="direct",
        specificity="named",
        embedding_int8=quant,
    )


def _axis(i: int) -> list[float]:
    v = [0.0] * _DIM
    v[i] = 1.0
    return v


@pytest.mark.unit
@pytest.mark.subsys_map
def test_orthogonal_groups_get_distinct_clusters() -> None:
    """Three mutually orthogonal topic directions yield three clusters, one per group."""
    atoms = [_atom(_axis(g)) for g in (0, 1, 2) for _ in range(2)]
    clusters = cluster_topics(atoms)
    assert len(clusters) == 3
    # Each orthogonal pair shares one id; the three ids are distinct.
    ids = [a.cluster_id for a in atoms]
    assert ids[0] == ids[1] and ids[2] == ids[3] and ids[4] == ids[5]
    assert len({ids[0], ids[2], ids[4]}) == 3


@pytest.mark.unit
@pytest.mark.subsys_map
def test_grouping_resists_chaining() -> None:
    """An arc of points (each close to its neighbor, ends far apart) must NOT collapse to one group.

    A cheaper grouping method would chain the whole arc into a single group;
    the current one splits it. This is the regression guard against swapping in
    a method that scrambles the partition.
    """
    arc = []
    for i in range(8):
        theta = math.radians(i * 20)
        v = [0.0] * _DIM
        v[0] = math.cos(theta)
        v[1] = math.sin(theta)
        arc.append(_atom(v))
    clusters = cluster_topics(arc)
    assert len(clusters) >= 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_heading_atoms_excluded_from_clustering() -> None:
    """Heading atoms are not clustered — they keep the default cluster_id of -1."""
    heading = _atom(_axis(0), kind="heading")
    body = [_atom(_axis(0)), _atom(_axis(0))]
    cluster_topics([heading, *body])
    assert heading.cluster_id == -1
    assert body[0].cluster_id == body[1].cluster_id != -1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_single_embedded_atom_falls_back_to_one_cluster() -> None:
    """Fewer than two embedded atoms collapse to a single fallback cluster."""
    clusters = cluster_topics([_atom(_axis(0))])
    assert len(clusters) == 1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_no_embeddings_returns_single_cluster() -> None:
    """Atoms without embeddings still resolve to one fallback cluster, not a crash."""
    bare = Atom(
        line=1,
        text="t",
        kind="excitation",
        charge="DIRECTIVE",
        charge_value=1,
        modality="direct",
        specificity="named",
    )
    clusters = cluster_topics([bare, bare])
    assert len(clusters) == 1

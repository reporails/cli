"""Mapper Stage 6: Cluster atoms into topic groups using stored embeddings.

Reuses the int8 vectors written by Stage 5 (Embed) — does not re-encode.
Dequantises to float32 in place for AgglomerativeClustering, then computes
L2-normalised centroids per cluster. Falls back to a single cluster when
fewer than two atoms have embeddings.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.platform.dto.ruleset import Atom, TopicCluster

# Topic clustering threshold (L2 distance on L2-normalized embeddings).
TOPIC_CLUSTER_THRESHOLD = 1.2


def _compute_centroid(embeddings_norm: Any, member_indices: list[int]) -> tuple[float, ...]:
    """Compute L2-normalized centroid from member vectors."""
    import numpy as np

    member_vecs = embeddings_norm[member_indices]
    mean_vec = member_vecs.mean(axis=0)
    norm = float(np.linalg.norm(mean_vec))
    if norm > 1e-12:
        mean_vec = mean_vec / norm
    return tuple(float(x) for x in mean_vec.tolist())


def _build_topic_clusters(
    clusters: dict[int, list[Atom]],
    indices: dict[int, list[int]],
    embeddings_norm: Any,
) -> list[TopicCluster]:
    """Build TopicCluster list from cluster assignments and normalized embeddings."""
    result: list[TopicCluster] = []
    for tid in sorted(clusters):
        cluster_atoms = clusters[tid]
        charged = [a for a in cluster_atoms if a.charge_value != 0]
        n_total = len(cluster_atoms)
        j = len(charged) / n_total if n_total else 0.0
        centroid = _compute_centroid(embeddings_norm, indices[tid])
        result.append(TopicCluster(topic_id=tid, atoms=cluster_atoms, charged=charged, j=j, centroid=centroid))
    return result


def _run_agglomerative_clustering(
    embedded: list[Atom],
) -> tuple[Any, Any]:
    """Run AgglomerativeClustering on embedded atoms. Returns (embeddings_norm, labels)."""
    import numpy as np
    from sklearn.cluster import AgglomerativeClustering
    from sklearn.preprocessing import normalize

    vecs = np.array(
        [list(a.embedding_int8) for a in embedded if a.embedding_int8 is not None],
        dtype=np.float32,
    )
    embeddings_norm = normalize(vecs, norm="l2")
    clustering = AgglomerativeClustering(
        n_clusters=None,
        distance_threshold=TOPIC_CLUSTER_THRESHOLD,
        metric="euclidean",
        linkage="average",
    )
    return embeddings_norm, clustering.fit_predict(embeddings_norm)


def cluster_topics(
    atoms: list[Atom],
) -> list[TopicCluster]:
    """Cluster atoms into topic groups using pre-computed embeddings.

    Uses AgglomerativeClustering with distance_threshold on the already-embedded
    int8 vectors from map_ruleset(). Does NOT re-encode — uses embedding_int8
    directly, dequantized to float32 for clustering.

    Falls back to single cluster when embeddings are missing.
    """
    exc = [a for a in atoms if a.kind != "heading"]
    if not exc:
        return []

    embedded = [a for a in exc if a.embedding_int8 is not None]
    if len(embedded) < 2:
        charged = [a for a in exc if a.charge_value != 0]
        j = len(charged) / len(exc) if exc else 0.0
        for a in exc:
            a.cluster_id = 0
        return [TopicCluster(topic_id=0, atoms=exc, charged=charged, j=j)]

    embeddings_norm, labels = _run_agglomerative_clustering(embedded)

    clusters: dict[int, list[Atom]] = {}
    indices: dict[int, list[int]] = {}
    for i, (atom, label) in enumerate(zip(embedded, labels, strict=True)):
        lbl = int(label)
        atom.cluster_id = lbl
        clusters.setdefault(lbl, []).append(atom)
        indices.setdefault(lbl, []).append(i)

    for a in exc:
        if a.embedding_int8 is None:
            a.cluster_id = -1

    return _build_topic_clusters(clusters, indices, embeddings_norm)

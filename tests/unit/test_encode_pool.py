"""Unit coverage for the encode thread-pool budget."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import encode_pool


@pytest.mark.unit
@pytest.mark.subsys_map
def test_run_buckets_preserves_submission_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pooled results come back in submission order, not completion order."""
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "4")
    tasks = [lambda i=i: i * 10 for i in range(20)]
    assert encode_pool.run_buckets(tasks) == [i * 10 for i in range(20)]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_run_buckets_serial_when_pool_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "1")
    assert encode_pool.run_buckets([lambda: 1, lambda: 2, lambda: 3]) == [1, 2, 3]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_run_buckets_single_task_never_pools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "8")
    assert encode_pool.run_buckets([lambda: 42]) == [42]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_run_buckets_empty() -> None:
    assert encode_pool.run_buckets([]) == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_workers_default_is_cpu_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILS_MAP_ENCODE_WORKERS", raising=False)
    assert encode_pool.encode_pool_workers() == encode_pool._cpu_count()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_workers_env_override_and_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "3")
    assert encode_pool.encode_pool_workers() == 3
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "0")
    assert encode_pool.encode_pool_workers() == 1
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "garbage")
    assert encode_pool.encode_pool_workers() == encode_pool._cpu_count()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_intra_op_coordinates_with_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """intra_op = 1 when the pool is on; cpu_count when off; explicit env wins."""
    monkeypatch.delenv("AILS_ORT_THREADS", raising=False)
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "8")
    assert encode_pool.ort_intra_threads() == 1
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "1")
    assert encode_pool.ort_intra_threads() == encode_pool._cpu_count()
    monkeypatch.setenv("AILS_ORT_THREADS", "2")
    assert encode_pool.ort_intra_threads() == 2

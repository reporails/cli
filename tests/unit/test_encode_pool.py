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
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "8")
    assert encode_pool.ort_intra_threads() == 1
    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "1")
    assert encode_pool.ort_intra_threads() == encode_pool._cpu_count()
    monkeypatch.setenv("AILS_ORT_THREADS", "2")
    assert encode_pool.ort_intra_threads() == 2


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("workers", ["1", "4"])
def test_run_buckets_on_done_once_per_task_from_calling_thread(monkeypatch: pytest.MonkeyPatch, workers: str) -> None:
    """The callback fires once per task, on the calling thread; results keep submission order."""
    import threading

    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", workers)
    caller = threading.get_ident()
    seen: list[tuple[int, int]] = []
    tasks = [lambda i=i: i * 10 for i in range(12)]
    results = encode_pool.run_buckets(tasks, lambda i: seen.append((i, threading.get_ident())))
    assert results == [i * 10 for i in range(12)]
    assert sorted(i for i, _ in seen) == list(range(12))
    assert {t for _, t in seen} == {caller}

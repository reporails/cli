"""Thread-pool budget for the warm-session encode.

The dominant cold-map cost is running the encoders, not loading them. The
resident encoder sessions are loaded once; the model runtime releases the GIL during
``session.run()``, so per-bucket forwards against one warm session parallelise
across a thread pool with no reload and no second copy.

Budget discipline: hold ``pool_workers * intra_op ~= cpu_count`` so threads do
not oversubscribe the cores. Default is pool = cpu_count, intra_op = 1. Setting
``AILS_MAP_ENCODE_WORKERS=1`` restores the single-threaded encode (intra_op then
falls back to cpu_count, so the serial path still uses the cores). An explicit
``AILS_ORT_THREADS`` always wins.

Concurrency-safety: `InferenceSession.run()` is safe under concurrent calls
(the model runtime, at its pinned minimum version); the byte-identity parity test
(`tests/integration/test_encode_pool_byte_identity.py`) is the load-bearing
guard that pool size never changes output.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed


def _cpu_count() -> int:
    return os.cpu_count() or 1


def encode_pool_workers() -> int:
    """Thread-pool size for the per-bucket encode. Default = cpu_count, min 1."""
    raw = os.environ.get("AILS_MAP_ENCODE_WORKERS", "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return max(1, _cpu_count())


def ort_intra_threads() -> int:
    """Intra-op thread count for an ONNX session, coordinated with the pool.

    An explicit ``AILS_ORT_THREADS`` wins (shard workers pin it to 1). Otherwise:
    when the encode pool is active (>1 worker) each `run()` is single intra-op
    (the pool provides the parallelism); with no pool the session uses cpu_count
    intra-op threads so the serial path still spreads across cores. Either way
    ``pool * intra_op ~= cpu_count``.
    """
    env = os.environ.get("AILS_ORT_THREADS")
    if env is not None:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    return 1 if encode_pool_workers() > 1 else _cpu_count()


def run_buckets[T](tasks: list[Callable[[], T]], on_done: Callable[[int], None] | None = None) -> list[T]:
    """Run per-bucket callables, returning results in submission order.

    Serial when the pool is disabled or there is only one bucket; otherwise
    concurrent over a bounded thread pool. ``on_done(index)`` is called once per
    finished task, always from the calling thread, in completion order.
    """
    workers = encode_pool_workers()
    if workers <= 1 or len(tasks) <= 1:
        results: list[T] = []
        for i, t in enumerate(tasks):
            results.append(t())
            if on_done is not None:
                on_done(i)
        return results
    with ThreadPoolExecutor(max_workers=min(workers, len(tasks))) as pool:
        futures = [pool.submit(t) for t in tasks]
        if on_done is not None:
            index = {f: i for i, f in enumerate(futures)}
            for f in as_completed(futures):
                f.result()
                on_done(index[f])
        return [f.result() for f in futures]

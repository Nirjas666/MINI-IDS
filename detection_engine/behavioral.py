"""Behavioral utilities: sliding-window rate trackers and bucketed counters.

This module provides two small, testable utilities for behavioral detectors:

- SlidingWindowCounter: simple deque-based per-key timestamp storage to
  compute counts within a sliding window (accurate but memory-per-event).

- BucketedCounter: fixed-time-bucket approximation useful for higher-throughput
  workloads where exact per-event storage is too heavy. Buckets are keyed by
  integer seconds (or configurable bucket size).

Both implementations are intentionally small and dependency-free so unit tests
and detectors can use them easily.
"""

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Tuple, Optional


class SlidingWindowCounter:
    """Count events per key within a sliding time window using deques.

    Note: This stores one timestamp per event and is exact. Good for tests
    and low-volume signals.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = int(window_seconds)
        # key -> deque[timestamp]
        self._events: Dict[str, Deque[float]] = defaultdict(deque)

    def add(self, key: str, timestamp: Optional[float] = None) -> None:
        ts = float(timestamp or time.time())
        q = self._events[key]
        q.append(ts)
        self._purge_old(q, ts)

    def _purge_old(self, q: Deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

    def count(self, key: str, now: Optional[float] = None) -> int:
        now = float(now or time.time())
        q = self._events.get(key)
        if not q:
            return 0
        self._purge_old(q, now)
        return len(q)

    def keys(self) -> List[str]:
        return list(self._events.keys())

    def clear(self, key: Optional[str] = None) -> None:
        if key is None:
            self._events.clear()
        else:
            self._events.pop(key, None)


class BucketedCounter:
    """Approximate counts using fixed-size time buckets.

    This trades some accuracy for reduced memory use. Each bucket is a dict
    mapping key->count; old buckets are recycled.
    """

    def __init__(self, window_seconds: int = 60, bucket_seconds: int = 1):
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be > 0")
        self.window_seconds = int(window_seconds)
        self.bucket_seconds = int(bucket_seconds)
        self._num_buckets = max(1, (self.window_seconds + self.bucket_seconds - 1) // self.bucket_seconds)
        # circular buffer of buckets: list[dict[key->count]]
        self._buckets: List[Dict[str, int]] = [defaultdict(int) for _ in range(self._num_buckets)]
        self._bucket_start_ts: int = int(time.time())  # epoch second for bucket index 0

    def _bucket_index(self, ts: Optional[float] = None) -> int:
        ts = int(ts or time.time())
        offset = (ts - self._bucket_start_ts) // self.bucket_seconds
        if offset < 0:
            # time moved backwards; reset buffer
            self._reset(ts)
            offset = 0
        if offset >= self._num_buckets:
            # advance the circular buffer to include ts
            steps = offset - (self._num_buckets - 1)
            self._advance(steps)
            offset = (ts - self._bucket_start_ts) // self.bucket_seconds
        return int(offset % self._num_buckets)

    def _advance(self, steps: int) -> None:
        # drop oldest `steps` buckets and reset them
        for _ in range(steps):
            # overwrite the oldest bucket
            oldest_idx = 0
            self._buckets.pop(0)
            self._buckets.append(defaultdict(int))
            self._bucket_start_ts += self.bucket_seconds

    def _reset(self, ts: int) -> None:
        self._buckets = [defaultdict(int) for _ in range(self._num_buckets)]
        self._bucket_start_ts = int(ts)

    def add(self, key: str, count: int = 1, timestamp: Optional[float] = None) -> None:
        ts = int(timestamp or time.time())
        idx = self._bucket_index(ts)
        self._buckets[idx][key] += int(count)

    def count(self, key: str, now: Optional[float] = None) -> int:
        now = int(now or time.time())
        # ensure buffer includes now
        self._bucket_index(now)
        total = 0
        for b in self._buckets:
            total += b.get(key, 0)
        return total

    def top_n(self, n: int = 10) -> List[Tuple[str, int]]:
        # aggregate counts across buckets and return top-n
        agg: Dict[str, int] = {}
        for b in self._buckets:
            for k, v in b.items():
                agg[k] = agg.get(k, 0) + v
        items = sorted(agg.items(), key=lambda iv: iv[1], reverse=True)
        return items[:n]

    def clear(self) -> None:
        for b in self._buckets:
            b.clear()


# Small convenience functions for tests and examples

def make_sliding(window_seconds: int = 60) -> SlidingWindowCounter:
    return SlidingWindowCounter(window_seconds=window_seconds)


def make_bucketed(window_seconds: int = 60, bucket_seconds: int = 1) -> BucketedCounter:
    return BucketedCounter(window_seconds=window_seconds, bucket_seconds=bucket_seconds)

"""Small in-process TTL cache for expensive read-only aggregates."""

import threading
import time
from typing import Any, Dict, Optional, Tuple

_CACHE: Dict[str, Tuple[float, Any]] = {}
_LOCK = threading.Lock()


def get_cached(key: str) -> Optional[Any]:
    """Return a cached value if it has not expired."""
    now = time.monotonic()
    with _LOCK:
        entry = _CACHE.get(key)
        if entry and entry[0] > now:
            return entry[1]
        if entry:
            _CACHE.pop(key, None)
    return None


def set_cached(key: str, value: Any, ttl_seconds: float) -> None:
    """Store a value with a monotonic TTL."""
    with _LOCK:
        _CACHE[key] = (time.monotonic() + ttl_seconds, value)


def invalidate_cache() -> None:
    """Clear all cached aggregates after a write."""
    with _LOCK:
        _CACHE.clear()

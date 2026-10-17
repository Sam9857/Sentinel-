"""Tiny thread-safe TTL cache so provider quotas (VirusTotal free = 4 req/min) survive a busy dashboard."""
import threading
import time

_lock = threading.Lock()
_store: dict = {}


def get(key: str):
    with _lock:
        item = _store.get(key)
        if not item:
            return None
        expires, value = item
        if expires < time.time():
            _store.pop(key, None)
            return None
        return value


def peek(key: str):
    """Alias of get(); named for call sites that must never trigger a network call."""
    return get(key)


def put(key: str, value, ttl: int = 3600):
    with _lock:
        _store[key] = (time.time() + ttl, value)
    return value


def clear():
    with _lock:
        _store.clear()

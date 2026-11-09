"""
core/rate_limiter.py
====================
Simple token-bucket rate limiter for polite scanning.

Why this matters
----------------
Public-facing targets usually have WAF / rate-limit / fail2ban rules.
A 400-request burst from a single IP is a quick way to get blocked,
and a blocked scan = wasted time. The scanner should look like a
normal human user: a few requests per second, with occasional pauses.

Usage
-----
    from core.rate_limiter import get_limiter, configure_limiter

    # Default: 5 req/s, burst of 10
    limiter = get_limiter()
    limiter.wait()              # blocks if needed
    requests.get(...)

    # Custom: 1 req/s, burst of 3 (very polite)
    configure_limiter(rate=1.0, burst=3)
    limiter = get_limiter()
    limiter.wait()

    # Or pass directly to the runner
    runner = ScannerRunner(rate_limiter=my_limiter)
"""

from __future__ import annotations

import threading
import time
from typing import Optional

_default_limiter: Optional["TokenBucket"] = None
_default_lock = threading.Lock()


class TokenBucket:
    """
    Thread-safe token-bucket rate limiter.

    A bucket holds up to `burst` tokens. It refills at `rate` tokens per
    second. Each call to `wait()` consumes one token; if none is available,
    the thread sleeps until one is.

    The bucket starts FULL so the first few requests are not delayed.
    """

    def __init__(self, rate: float = 5.0, burst: int = 10):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")
        self.rate = float(rate)
        self.burst = int(burst)
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._stats = {"waits": 0, "total_acquired": 0, "total_sleep_ms": 0.0, "total_waited_ms": 0.0}

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def wait(self, tokens: int = 1) -> None:
        """Block until `tokens` tokens are available, then consume them."""
        if tokens > self.burst:
            raise ValueError(f"cannot request {tokens} tokens, bucket size is {self.burst}")
        with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    self._stats["total_acquired"] += tokens
                    return
                # Sleep outside the lock? No — keep it to avoid races.
                deficit = tokens - self._tokens
                sleep_s = deficit / self.rate
                self._stats["waits"] += 1
                self._stats["total_sleep_ms"] += sleep_s * 1000
                self._stats["total_waited_ms"] += sleep_s * 1000
                time.sleep(sleep_s)

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking version. Returns True if it got the tokens."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                self._stats["total_acquired"] += tokens
                return True
            return False

    @property
    def stats(self) -> dict:
        return dict(self._stats)


def configure_limiter(rate: float = 5.0, burst: int = 10) -> TokenBucket:
    """Replace the global default limiter. Returns the new instance."""
    global _default_limiter
    with _default_lock:
        _default_limiter = TokenBucket(rate=rate, burst=burst)
    return _default_limiter


def get_limiter() -> TokenBucket:
    """Get the global default limiter, creating it on first use."""
    global _default_limiter
    if _default_limiter is None:
        with _default_lock:
            if _default_limiter is None:
                _default_limiter = TokenBucket(rate=5.0, burst=10)
    return _default_limiter


def reset_for_testing() -> None:
    """Drop the global limiter (for unit tests)."""
    global _default_limiter
    with _default_lock:
        _default_limiter = None


# ---------------------------------------------------------------------------
# Backwards-compatible alias (used by attack_surface.py CLI)
# ---------------------------------------------------------------------------

def configure(rate: float = 5.0, burst: int = 10) -> TokenBucket:
    """Alias for configure_limiter(). Returns the configured limiter."""
    return configure_limiter(rate=rate, burst=burst)

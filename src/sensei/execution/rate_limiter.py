"""Rate limiting engine to ensure target hosts are never hammered."""

import time
import threading
from typing import Dict


class RateLimiter:
    """Thread-safe Token Bucket Rate Limiter."""

    def __init__(self, default_rate: float = 2.0, burst: int = 5):
        """
        :param default_rate: Allowed calls per second.
        :param burst: Maximum token capacity for short bursts.
        """
        self.default_rate = default_rate
        self.burst = burst
        self._tokens: Dict[str, float] = {}
        self._last_updated: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, target_key: str = "global") -> None:
        """Blocks until a token is available for the given target."""
        while True:
            with self._lock:
                now = time.monotonic()
                if target_key not in self._tokens:
                    self._tokens[target_key] = float(self.burst)
                    self._last_updated[target_key] = now

                # Replenish tokens based on elapsed time
                elapsed = now - self._last_updated[target_key]
                self._tokens[target_key] = min(
                    float(self.burst),
                    self._tokens[target_key] + elapsed * self.default_rate
                )
                self._last_updated[target_key] = now

                if self._tokens[target_key] >= 1.0:
                    self._tokens[target_key] -= 1.0
                    return

                # Calculate sleep duration needed for 1 token
                sleep_needed = (1.0 - self._tokens[target_key]) / self.default_rate

            time.sleep(max(0.05, sleep_needed))


_global_rate_limiter = RateLimiter(default_rate=2.0)


def get_rate_limiter() -> RateLimiter:
    """Return global rate limiter."""
    return _global_rate_limiter

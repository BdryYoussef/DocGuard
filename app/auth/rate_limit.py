"""Bounded in-process login throttling for a single DocGuard instance."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass

_MAX_TRACKED_KEYS = 10_000


@dataclass(frozen=True, slots=True)
class LoginRateLimitResult:
    allowed: bool


class LoginRateLimiter:
    def __init__(self, *, per_minute: int, per_hour: int) -> None:
        self._per_minute = per_minute
        self._per_hour = per_hour
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, source_address: str, normalized_username: str) -> LoginRateLimitResult:
        now = time.monotonic()
        keys = self._keys(source_address, normalized_username)
        with self._lock:
            self._prune(now)
            allowed = all(self._key_allowed(key, now) for key in keys)
        return LoginRateLimitResult(allowed=allowed)

    def record_failure(self, source_address: str, normalized_username: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            for key in self._keys(source_address, normalized_username):
                if key not in self._attempts and len(self._attempts) >= _MAX_TRACKED_KEYS:
                    continue
                self._attempts.setdefault(key, deque()).append(now)

    def clear_username(self, normalized_username: str) -> None:
        with self._lock:
            self._attempts.pop(self._username_key(normalized_username), None)

    def _key_allowed(self, key: str, now: float) -> bool:
        attempts = self._attempts.get(key, ())
        minute_count = sum(moment > now - 60 for moment in attempts)
        return minute_count < self._per_minute and len(attempts) < self._per_hour

    def _prune(self, now: float) -> None:
        cutoff = now - 3_600
        for key in list(self._attempts):
            attempts = self._attempts[key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                del self._attempts[key]

    @classmethod
    def _keys(cls, source_address: str, normalized_username: str) -> tuple[str, str]:
        source_digest = hashlib.sha256(source_address.encode("utf-8")).hexdigest()
        return f"source:{source_digest}", cls._username_key(normalized_username)

    @staticmethod
    def _username_key(normalized_username: str) -> str:
        digest = hashlib.sha256(normalized_username.encode("utf-8")).hexdigest()
        return f"username:{digest}"


__all__ = ["LoginRateLimitResult", "LoginRateLimiter"]

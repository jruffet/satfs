# SPDX-License-Identifier: MIT

import time
from typing import Any, Optional


class TTLCache:
    def __init__(self, ttl: int = 10) -> None:
        self.ttl = ttl
        self.cache = {}

    def _cleanup(self) -> None:
        now = time.time()
        expired_keys = [key for key, (_, timestamp) in self.cache.items() if now - timestamp >= self.ttl]
        for key in expired_keys:
            del self.cache[key]

    def get(self, key: Any) -> Optional[Any]:
        """Retrieve a value from the cache if it is still valid."""
        self._cleanup()
        return self.cache.get(key, (None,))[0]

    def set(self, key: Any, value: Any) -> None:
        """Store a value in the cache with the current timestamp."""
        self.cache[key] = (value, time.time())

    def set_ttl(self, new_ttl: int) -> None:
        self.ttl = new_ttl

    def clear(self) -> None:
        for key in self.cache.keys():
            del self.cache[key]

    # Make it behave like a dictionary
    def __getitem__(self, key: Any) -> Any:
        result = self.get(key)
        if result is None:
            raise KeyError(f"Key {key} not found or expired")
        return result

    def __setitem__(self, key: Any, value: Any) -> None:
        self.set(key, value)

    def __delitem__(self, key: Any) -> None:
        if key in self.cache:
            del self.cache[key]
        else:
            raise KeyError(f"Key {key} not found")

    def __contains__(self, key: Any) -> bool:
        return self.get(key) is not None

"""
Throttled logging utilities for cognito-auth.

Reduces log noise by emitting INFO only on first-seen per user within a
TTL window, then DEBUG for subsequent occurrences.
"""

import logging
import os

from cachetools import TTLCache

_DEFAULT_TTL = 300  # 5 minutes


class ThrottledLogger:
    """
    Logger wrapper that emits INFO only on first-seen per user within
    a TTL window, then DEBUG for subsequent occurrences.

    Each instance maintains its own cache, so modules are naturally isolated.

    Args:
        logger: The underlying Python logger to delegate to.
        ttl: Cache TTL in seconds. Defaults to COGNITO_AUTH_LOG_TTL env var
            or 300 seconds (5 minutes).
        maxsize: Maximum number of user keys to track. Defaults to 1024.

    Example:
        >>> import logging
        >>> logger = logging.getLogger(__name__)
        >>> _throttled = ThrottledLogger(logger)
        >>> _throttled.info(user.sub, "User authenticated: email=%s", user.email)
    """

    def __init__(
        self,
        logger: logging.Logger,
        ttl: int | None = None,
        maxsize: int = 1024,
    ):
        self._logger = logger
        _ttl = ttl or int(os.getenv("COGNITO_AUTH_LOG_TTL", _DEFAULT_TTL))
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=_ttl)

    def info(self, user_key: str, msg: str, *args):
        """
        Log at INFO if user_key is first-seen within the TTL window,
        otherwise log at DEBUG.

        Args:
            user_key: Unique identifier for the user (e.g., sub or email).
            msg: Log message format string.
            *args: Arguments for the format string.
        """
        if user_key not in self._cache:
            self._cache[user_key] = True
            self._logger.info(msg, *args)
        else:
            self._logger.debug(msg, *args)

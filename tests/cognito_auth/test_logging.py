"""Tests for ThrottledLogger."""

import logging

import pytest

from cognito_auth._logging import ThrottledLogger


@pytest.fixture
def logger():
    """Create a test logger with a handler that captures records."""
    test_logger = logging.getLogger("test.throttled")
    test_logger.setLevel(logging.DEBUG)
    test_logger.handlers.clear()
    return test_logger


@pytest.fixture
def handler(logger):
    """Attach a handler that captures log records."""

    class RecordCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record):
            self.records.append(record)

    capture = RecordCapture()
    capture.setLevel(logging.DEBUG)
    logger.addHandler(capture)
    return capture


class TestThrottledLogger:
    """Tests for ThrottledLogger.info() throttling behaviour."""

    def test_first_call_logs_at_info(self, logger, handler):
        """First call for a user should log at INFO level."""
        throttled = ThrottledLogger(logger, ttl=60)

        throttled.info("user-1", "Hello %s", "world")

        assert len(handler.records) == 1
        assert handler.records[0].levelno == logging.INFO
        assert handler.records[0].getMessage() == "Hello world"

    def test_second_call_same_user_logs_at_debug(self, logger, handler):
        """Subsequent calls for the same user should log at DEBUG."""
        throttled = ThrottledLogger(logger, ttl=60)

        throttled.info("user-1", "First call")
        throttled.info("user-1", "Second call")

        assert len(handler.records) == 2
        assert handler.records[0].levelno == logging.INFO
        assert handler.records[1].levelno == logging.DEBUG

    def test_different_users_each_log_at_info(self, logger, handler):
        """Different user keys should each get their own first INFO log."""
        throttled = ThrottledLogger(logger, ttl=60)

        throttled.info("user-1", "User 1 first")
        throttled.info("user-2", "User 2 first")
        throttled.info("user-1", "User 1 second")

        assert len(handler.records) == 3
        assert handler.records[0].levelno == logging.INFO
        assert handler.records[1].levelno == logging.INFO
        assert handler.records[2].levelno == logging.DEBUG

    def test_separate_instances_are_independent(self, logger, handler):
        """Two ThrottledLogger instances should track users independently."""
        throttled_a = ThrottledLogger(logger, ttl=60)
        throttled_b = ThrottledLogger(logger, ttl=60)

        throttled_a.info("user-1", "Instance A first")
        throttled_b.info("user-1", "Instance B first")

        assert len(handler.records) == 2
        assert handler.records[0].levelno == logging.INFO
        assert handler.records[1].levelno == logging.INFO

    def test_ttl_expiry_resets_to_info(self, logger, handler):
        """After TTL expires, user should log at INFO again."""
        throttled = ThrottledLogger(logger, ttl=1)

        throttled.info("user-1", "First call")
        assert handler.records[0].levelno == logging.INFO

        throttled.info("user-1", "Second call (cached)")
        assert handler.records[1].levelno == logging.DEBUG

        # Manually expire the cache to simulate TTL expiry
        throttled._cache.clear()

        throttled.info("user-1", "After expiry")
        assert handler.records[2].levelno == logging.INFO

    def test_format_args_are_passed_correctly(self, logger, handler):
        """Format arguments should be passed through to the logger."""
        throttled = ThrottledLogger(logger, ttl=60)

        throttled.info("user-1", "email=%s, groups=%s", "a@b.com", ["admin"])

        assert handler.records[0].getMessage() == "email=a@b.com, groups=['admin']"

    def test_maxsize_evicts_oldest(self, logger, handler):
        """When maxsize is exceeded, oldest entries should be evicted."""
        throttled = ThrottledLogger(logger, ttl=60, maxsize=2)

        throttled.info("user-1", "User 1 first")
        throttled.info("user-2", "User 2 first")
        throttled.info("user-3", "User 3 first")  # evicts user-1

        # user-1 was evicted, so should log at INFO again
        throttled.info("user-1", "User 1 again")

        assert handler.records[0].levelno == logging.INFO  # user-1 first
        assert handler.records[1].levelno == logging.INFO  # user-2 first
        assert handler.records[2].levelno == logging.INFO  # user-3 first
        assert handler.records[3].levelno == logging.INFO  # user-1 re-seen

    def test_env_var_overrides_default_ttl(self, monkeypatch, logger, handler):
        """COGNITO_AUTH_LOG_TTL env var should override the default TTL."""
        monkeypatch.setenv("COGNITO_AUTH_LOG_TTL", "120")

        throttled = ThrottledLogger(logger)

        # Verify cache was created with env var TTL
        assert throttled._cache.ttl == 120

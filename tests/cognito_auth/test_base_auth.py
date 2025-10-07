import os
import warnings
from unittest.mock import MagicMock, patch

import pytest

from cognito_auth import Authorizer, User
from cognito_auth._base_auth import BaseAuth


@pytest.fixture
def suppress_dev_warning():
    """
    Suppress the dev mode warning for tests that specifically test dev mode.

    Dev mode triggers a UserWarning about being enabled, which is intentional
    in production but noisy in tests. Only use this fixture in tests that
    specifically need to test dev mode behavior.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        yield


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authorizer.clear_config_cache()
    return


# Tests for initialization


def test_init_auto_loads_from_config(tmp_path):
    """BaseAuth() auto-loads authorizer from environment variables"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        auth = BaseAuth()
        assert auth.authorizer is not None
        assert len(auth.authorizer.rules) == 1


def test_init_with_custom_authorizer():
    """BaseAuth accepts custom authorizer"""
    authorizer = Authorizer.from_lists(allowed_groups=["custom"])
    auth = BaseAuth(authorizer=authorizer)
    assert auth.authorizer is authorizer


def test_init_sets_default_config(tmp_path):
    """Default region and redirect_url are set"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["test"], "allowed_users": [], "require_all": false}'
    )

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        auth = BaseAuth()
        assert auth.region == "eu-west-2"
        assert auth.redirect_url == "https://gds-idea.click/401.html"


def test_init_accepts_custom_config(tmp_path):
    """Custom region and redirect_url can be provided"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["test"], "allowed_users": [], "require_all": false}'
    )

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        auth = BaseAuth(region="us-east-1", redirect_url="https://custom.com/401")
        assert auth.region == "us-east-1"
        assert auth.redirect_url == "https://custom.com/401"


# Tests for dev mode detection


def test_dev_mode_enabled(suppress_dev_warning):
    """Dev mode is detected from environment variable"""
    with patch.dict(os.environ, {"COGNITO_AUTH_DEV_MODE": "true"}):
        authorizer = Authorizer.from_lists(allowed_groups=["test"])
        auth = BaseAuth(authorizer=authorizer)
        assert auth.dev_mode is True


def test_dev_mode_accepts_various_values(suppress_dev_warning):
    """Dev mode accepts true/1/yes (case insensitive)"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    for value in ["true", "1", "yes", "True", "YES"]:
        with patch.dict(os.environ, {"COGNITO_AUTH_DEV_MODE": value}):
            auth = BaseAuth(authorizer=authorizer)
            assert auth.dev_mode is True


def test_dev_mode_disabled_by_default():
    """Dev mode is disabled when env var not set"""
    with patch.dict(os.environ, {}, clear=True):
        authorizer = Authorizer.from_lists(allowed_groups=["test"])
        auth = BaseAuth(authorizer=authorizer)
        assert auth.dev_mode is False


def test_dev_mode_triggers_warning():
    """Dev mode triggers UserWarning"""
    with patch.dict(os.environ, {"COGNITO_AUTH_DEV_MODE": "true"}):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            authorizer = Authorizer.from_lists(allowed_groups=["test"])
            BaseAuth(authorizer=authorizer)

            assert len(w) == 1
            assert "COGNITO_AUTH_DEV_MODE" in str(w[0].message)
            assert "NEVER" in str(w[0].message)


# Tests for _get_header helper


def test_get_header_finds_capitalized():
    """_get_header finds capitalized header"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    headers = {"X-Amzn-Oidc-Data": "token-value"}

    value = auth._get_header(headers, "X-Amzn-Oidc-Data")
    assert value == "token-value"


def test_get_header_finds_lowercase():
    """_get_header finds lowercase header"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    headers = {"x-amzn-oidc-data": "token-value"}

    value = auth._get_header(headers, "X-Amzn-Oidc-Data")
    assert value == "token-value"


def test_get_header_prefers_original_case():
    """_get_header prefers original case when both exist"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    headers = {
        "X-Amzn-Oidc-Data": "capitalized",
        "x-amzn-oidc-data": "lowercase",
    }

    value = auth._get_header(headers, "X-Amzn-Oidc-Data")
    assert value == "capitalized"


def test_get_header_returns_none_when_missing():
    """_get_header returns None when header not found"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    headers = {}

    value = auth._get_header(headers, "X-Amzn-Oidc-Data")
    assert value is None


# Tests for _get_user_from_headers


def test_get_user_from_headers_returns_mock_in_dev_mode(suppress_dev_warning):
    """_get_user_from_headers returns mock user in dev mode when headers missing"""
    with patch.dict(os.environ, {"COGNITO_AUTH_DEV_MODE": "true"}):
        authorizer = Authorizer.from_lists(allowed_groups=["test"])
        auth = BaseAuth(authorizer=authorizer)

        user = auth._get_user_from_headers({})

        assert user is not None
        assert user.is_authenticated is True


def test_get_user_from_headers_creates_user_with_verify_tokens():
    """_get_user_from_headers creates User with verify_tokens=True"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    headers = {
        "X-Amzn-Oidc-Data": "oidc-token",
        "X-Amzn-Oidc-Accesstoken": "access-token",
    }

    with patch("cognito_auth._base_auth.User") as mock_user_class:
        mock_user_class.return_value = User.create_mock()
        auth._get_user_from_headers(headers)

        mock_user_class.assert_called_once_with(
            oidc_data_header="oidc-token",
            access_token_header="access-token",
            region="eu-west-2",
            verify_tokens=True,
        )


# Tests for _is_authorized


def test_is_authorized_allows_user_with_no_authorizer(tmp_path):
    """_is_authorized returns True when no authorizer set"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["test"], "allowed_users": [], "require_all": false}'
    )

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        auth = BaseAuth()
        auth.authorizer = None  # Remove authorizer

        user = User.create_mock()
        assert auth._is_authorized(user) is True


def test_is_authorized_delegates_to_authorizer():
    """_is_authorized calls authorizer.is_authorized"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    user = User.create_mock()

    # Mock the authorizer's is_authorized method
    auth.authorizer.is_authorized = MagicMock(return_value=True)

    result = auth._is_authorized(user)

    auth.authorizer.is_authorized.assert_called_once_with(user)
    assert result is True


def test_is_authorized_respects_authorizer_rejection():
    """_is_authorized returns False when authorizer rejects"""
    authorizer = Authorizer.from_lists(allowed_groups=["test"])
    auth = BaseAuth(authorizer=authorizer)
    user = User.create_mock()

    # Mock the authorizer to reject
    auth.authorizer.is_authorized = MagicMock(return_value=False)

    result = auth._is_authorized(user)

    assert result is False

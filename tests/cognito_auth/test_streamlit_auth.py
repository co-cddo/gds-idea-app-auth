import os
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from cognito_auth import Authoriser, User
from cognito_auth.exceptions import ExpiredTokenError, MissingTokenError
from cognito_auth.streamlit import StreamlitAuth


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authoriser.clear_config_cache()
    return


@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    with patch("cognito_auth.streamlit.st") as mock_st:
        # Mock context.headers
        mock_st.context.headers = {}
        # Mock session_state as a dict
        mock_st.session_state = {}
        # Mock st.stop() to raise exception (simulates stopping execution)
        mock_st.stop.side_effect = SystemExit("st.stop() called")
        yield mock_st


@pytest.fixture
def auth_config_file(tmp_path):
    """Create auth config file"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )
    return config_file


@pytest.fixture
def streamlit_auth(auth_config_file):
    """Create StreamlitAuth instance with config"""
    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(auth_config_file)}, clear=True
    ):
        yield StreamlitAuth()


# Tests for get_auth_user()


def test_get_auth_user_returns_user_when_authorised(mock_streamlit, streamlit_auth):
    """get_auth_user returns user when authentication and authorisation succeed"""
    mock_user = User.create_mock(groups=["developers"])

    with (
        patch.object(streamlit_auth, "_get_user_from_headers", return_value=mock_user),
        patch.object(streamlit_auth, "_is_authorised", return_value=True),
    ):
        user = streamlit_auth.get_auth_user()
        assert user == mock_user


def test_get_auth_user_stops_when_unauthorised(mock_streamlit, streamlit_auth):
    """get_auth_user calls st.stop() when user is not authorised"""
    mock_user = User.create_mock(groups=["other-group"])

    with (
        patch.object(streamlit_auth, "_get_user_from_headers", return_value=mock_user),
        patch.object(streamlit_auth, "_is_authorised", return_value=False),
    ):
        with pytest.raises(SystemExit, match="st.stop"):
            streamlit_auth.get_auth_user()

        # Verify st.error and st.info were called
        mock_streamlit.error.assert_called_once()
        mock_streamlit.info.assert_called_once()
        mock_streamlit.stop.assert_called_once()


def test_get_auth_user_stops_on_authentication_failure(mock_streamlit, streamlit_auth):
    """get_auth_user calls st.stop() when authentication fails"""
    with patch.object(
        streamlit_auth, "_get_user_from_headers", side_effect=Exception("Auth failed")
    ):
        with pytest.raises(SystemExit, match="st.stop"):
            streamlit_auth.get_auth_user()

        # Verify st.error and st.info were called
        mock_streamlit.error.assert_called_once()
        mock_streamlit.info.assert_called_once()
        mock_streamlit.stop.assert_called_once()


def test_get_auth_user_uses_streamlit_context_headers(mock_streamlit, streamlit_auth):
    """get_auth_user extracts headers from st.context.headers"""
    # Set up mock headers
    mock_streamlit.context.headers = {
        "X-Amzn-Oidc-Data": "mock-oidc-token",
        "X-Amzn-Oidc-Accesstoken": "mock-access-token",
    }

    mock_user = User.create_mock(groups=["developers"])

    with (
        patch.object(
            streamlit_auth, "_get_user_from_headers", return_value=mock_user
        ) as mock_get_user,
        patch.object(streamlit_auth, "_is_authorised", return_value=True),
    ):
        streamlit_auth.get_auth_user()

        # Verify _get_user_from_headers was called with the headers dict
        mock_get_user.assert_called_once()
        called_headers = mock_get_user.call_args[0][0]
        assert called_headers["X-Amzn-Oidc-Data"] == "mock-oidc-token"
        assert called_headers["X-Amzn-Oidc-Accesstoken"] == "mock-access-token"


# Tests for session state caching behavior


def test_get_auth_user_caches_user_in_session_state(mock_streamlit, streamlit_auth):
    """get_auth_user caches authenticated user in st.session_state"""
    mock_user = User.create_mock(groups=["developers"])

    with (
        patch.object(streamlit_auth, "_get_user_from_headers", return_value=mock_user),
        patch.object(streamlit_auth, "_is_authorised", return_value=True),
    ):
        user = streamlit_auth.get_auth_user()

        # Verify user is cached
        assert "_cognito_auth_user" in mock_streamlit.session_state
        assert mock_streamlit.session_state["_cognito_auth_user"] == mock_user
        assert user == mock_user


def test_get_auth_user_updates_cache_when_headers_available(
    mock_streamlit, streamlit_auth
):
    """get_auth_user always tries headers first and updates cache"""
    # Create mock user with future expiration
    future_exp = datetime.now() + timedelta(hours=1)
    old_user = User.create_mock(email="old@example.com", groups=["developers"])
    old_user._access_claims["exp"] = int(future_exp.timestamp())

    new_user = User.create_mock(email="new@example.com", groups=["developers"])
    new_user._access_claims["exp"] = int(future_exp.timestamp())

    # Pre-populate cache with old user
    mock_streamlit.session_state["_cognito_auth_user"] = old_user

    with (
        patch.object(
            streamlit_auth, "_get_user_from_headers", return_value=new_user
        ) as mock_get_user,
        patch.object(streamlit_auth, "_is_authorised", return_value=True),
    ):
        user = streamlit_auth.get_auth_user()

        # Should always try headers first (even with cache)
        mock_get_user.assert_called_once()
        # Should return and cache the NEW user from headers
        assert user == new_user
        assert user.email == "new@example.com"
        assert mock_streamlit.session_state["_cognito_auth_user"] == new_user


def test_get_auth_user_checks_cached_token_expiration(mock_streamlit, streamlit_auth):
    """get_auth_user detects expired cached token and stops execution"""
    # Create mock user with PAST expiration
    past_exp = datetime.now() - timedelta(hours=1)
    mock_user = User.create_mock(groups=["developers"])
    # Set expiry in access_claims (not oidc_claims) since user.exp reads from there
    mock_user._access_claims["exp"] = int(past_exp.timestamp())

    # Pre-populate cache with expired user
    mock_streamlit.session_state["_cognito_auth_user"] = mock_user

    # Trigger ExpiredTokenError to reach cache expiration check
    with patch.object(
        streamlit_auth,
        "_get_user_from_headers",
        side_effect=ExpiredTokenError("ALB token expired"),
    ):
        with pytest.raises(SystemExit, match="st.stop"):
            streamlit_auth.get_auth_user()

        # Verify cache was cleared
        assert "_cognito_auth_user" not in mock_streamlit.session_state
        # Verify error messages shown
        mock_streamlit.error.assert_called_once()
        assert "expired" in mock_streamlit.error.call_args[0][0].lower()


def test_get_auth_user_fails_on_missing_headers(mock_streamlit, streamlit_auth):
    """get_auth_user shows error when headers are missing (misconfiguration)"""
    # Create mock user with future expiration
    future_exp = datetime.now() + timedelta(hours=1)
    mock_user = User.create_mock(groups=["developers"])
    mock_user._access_claims["exp"] = int(future_exp.timestamp())

    # Pre-populate cache (doesn't matter, should not use it)
    mock_streamlit.session_state["_cognito_auth_user"] = mock_user

    # Simulate missing headers (misconfiguration or ALB bypass)
    with patch.object(
        streamlit_auth,
        "_get_user_from_headers",
        side_effect=MissingTokenError("No headers"),
    ):
        with pytest.raises(SystemExit, match="st.stop"):
            streamlit_auth.get_auth_user()

        # Should show error (not use cache)
        mock_streamlit.error.assert_called_once()
        mock_streamlit.stop.assert_called_once()


def test_get_auth_user_handles_expired_token_with_no_cache(
    mock_streamlit, streamlit_auth
):
    """get_auth_user fails when ExpiredTokenError and no cached user"""
    # No cached user - should fail with initialization error
    with patch.object(
        streamlit_auth,
        "_get_user_from_headers",
        side_effect=ExpiredTokenError("Token expired"),
    ):
        with pytest.raises(SystemExit, match="st.stop"):
            streamlit_auth.get_auth_user()

        # Verify error shown (falls back to cache, but no cache exists)
        mock_streamlit.error.assert_called_once()
        assert "initialization" in mock_streamlit.error.call_args[0][0].lower()


def test_get_auth_user_uses_cache_when_headers_expired(
    mock_streamlit, streamlit_auth
):
    """get_auth_user falls back to cache when headers present but expired (normal)"""
    # Create mock user with future expiration
    future_exp = datetime.now() + timedelta(hours=1)
    mock_user = User.create_mock(groups=["developers"])
    mock_user._access_claims["exp"] = int(future_exp.timestamp())

    # Pre-populate cache with valid token
    mock_streamlit.session_state["_cognito_auth_user"] = mock_user

    # Headers present but ALB token expired (stale headers)
    with patch.object(
        streamlit_auth,
        "_get_user_from_headers",
        side_effect=ExpiredTokenError("ALB token expired"),
    ):
        user = streamlit_auth.get_auth_user()

        # Should return cached user (access token still valid)
        assert user == mock_user


def test_get_auth_user_prefers_fresh_headers_over_cache(mock_streamlit, streamlit_auth):
    """get_auth_user always tries headers first, even when cache exists"""
    old_user = User.create_mock(email="old@example.com", groups=["developers"])
    new_user = User.create_mock(email="new@example.com", groups=["developers"])

    # Pre-populate cache with old user
    mock_streamlit.session_state["_cognito_auth_user"] = old_user

    # Headers present with new user (ALB refreshed tokens)
    with (
        patch.object(
            streamlit_auth, "_get_user_from_headers", return_value=new_user
        ) as mock_get_user,
        patch.object(streamlit_auth, "_is_authorised", return_value=True),
    ):
        user = streamlit_auth.get_auth_user()

        # Should return NEW user from headers, not cached old user
        assert user == new_user
        assert user.email == "new@example.com"
        # Verify headers were checked
        mock_get_user.assert_called_once()
        # Verify cache updated
        assert mock_streamlit.session_state["_cognito_auth_user"] == new_user

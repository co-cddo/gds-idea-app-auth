import os
from unittest.mock import patch

import pytest

from cognito_auth import Authorizer, User
from cognito_auth.streamlit import StreamlitAuth


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authorizer.clear_config_cache()
    return


@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    with patch("cognito_auth.streamlit.st") as mock_st:
        # Mock context.headers
        mock_st.context.headers = {}
        # Mock st.stop() to raise exception (simulates stopping execution)
        mock_st.stop.side_effect = SystemExit("st.stop() called")
        yield mock_st


# Tests for get_auth_user()


def test_get_auth_user_returns_user_when_authorised(mock_streamlit, tmp_path):
    """get_auth_user returns user when authentication and authorisation succeed"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    mock_user = User.create_mock(groups=["developers"])

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        auth = StreamlitAuth()

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=True),
        ):
            user = auth.get_auth_user()
            assert user == mock_user


def test_get_auth_user_stops_when_unauthorised(mock_streamlit, tmp_path):
    """get_auth_user calls st.stop() when user is not authorised"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    mock_user = User.create_mock(groups=["other-group"])

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        auth = StreamlitAuth()

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=False),
        ):
            with pytest.raises(SystemExit, match="st.stop"):
                auth.get_auth_user()

            # Verify st.error and st.info were called
            mock_streamlit.error.assert_called_once()
            mock_streamlit.info.assert_called_once()
            mock_streamlit.stop.assert_called_once()


def test_get_auth_user_stops_on_authentication_failure(mock_streamlit, tmp_path):
    """get_auth_user calls st.stop() when authentication fails"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        auth = StreamlitAuth()

        with patch.object(
            auth, "_get_user_from_headers", side_effect=Exception("Auth failed")
        ):
            with pytest.raises(SystemExit, match="st.stop"):
                auth.get_auth_user()

            # Verify st.error and st.info were called
            mock_streamlit.error.assert_called_once()
            mock_streamlit.info.assert_called_once()
            mock_streamlit.stop.assert_called_once()


def test_get_auth_user_uses_streamlit_context_headers(mock_streamlit, tmp_path):
    """get_auth_user extracts headers from st.context.headers"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    # Set up mock headers
    mock_streamlit.context.headers = {
        "X-Amzn-Oidc-Data": "mock-oidc-token",
        "X-Amzn-Oidc-Accesstoken": "mock-access-token",
    }

    mock_user = User.create_mock(groups=["developers"])

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        auth = StreamlitAuth()

        with (
            patch.object(
                auth, "_get_user_from_headers", return_value=mock_user
            ) as mock_get_user,
            patch.object(auth, "_is_authorised", return_value=True),
        ):
            auth.get_auth_user()

            # Verify _get_user_from_headers was called with the headers dict
            mock_get_user.assert_called_once()
            called_headers = mock_get_user.call_args[0][0]
            assert called_headers["X-Amzn-Oidc-Data"] == "mock-oidc-token"
            assert called_headers["X-Amzn-Oidc-Accesstoken"] == "mock-access-token"

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognito_auth import Authoriser, User
from cognito_auth.gradio import GradioAuth


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authoriser.clear_config_cache()
    return


# Tests for protect_app()


def test_protect_app_adds_middleware(tmp_path):
    """protect_app adds middleware to FastAPI app"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        app = FastAPI()
        auth = GradioAuth()

        initial_middleware_count = len(app.user_middleware)
        auth.protect_app(app)

        # Verify middleware was added
        assert len(app.user_middleware) > initial_middleware_count


def test_protect_app_middleware_redirects_unauthorised_user(tmp_path):
    """protect_app middleware redirects unauthorised users"""
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
        app = FastAPI()
        auth = GradioAuth()

        @app.get("/")
        def index():
            return {"message": "Success"}

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=False),
        ):
            auth.protect_app(app)
            client = TestClient(app)

            response = client.get(
                "/",
                headers={"X-Amzn-Oidc-Data": "token"},
                follow_redirects=False,
            )

            # Should redirect
            assert response.status_code == 307
            assert auth.redirect_url in response.headers["location"]


# Tests for get_auth_user()


def test_get_auth_user_retrieves_from_request_state_when_protect_app_used(tmp_path):
    """get_auth_user retrieves user from request.state when protect_app used"""
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
        auth = GradioAuth()

        # Mock a Gradio request with state containing user
        mock_request = MagicMock()
        mock_request.state.user = mock_user

        user = auth.get_auth_user(mock_request)
        assert user == mock_user


def test_get_auth_user_validates_on_demand_for_standalone_gradio(tmp_path):
    """get_auth_user validates on-demand for standalone Gradio"""
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
        auth = GradioAuth()

        # Mock a Gradio request without state.user (standalone mode)
        mock_request = MagicMock()
        mock_request.headers = {"X-Amzn-Oidc-Data": "token"}
        # Simulate no state.user
        del mock_request.state.user

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=True),
        ):
            user = auth.get_auth_user(mock_request)
            assert user == mock_user


def test_get_auth_user_raises_permission_error_when_unauthorised(tmp_path):
    """get_auth_user raises PermissionError when user not authorised"""
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
        auth = GradioAuth()

        # Mock a Gradio request without state.user (standalone mode)
        mock_request = MagicMock()
        mock_request.headers = {"X-Amzn-Oidc-Data": "token"}
        del mock_request.state.user

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=False),
        ):
            with pytest.raises(PermissionError, match="Access denied"):
                auth.get_auth_user(mock_request)


def test_protect_app_allows_authorised_user(tmp_path):
    """protect_app middleware allows authorised users through"""
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
        app = FastAPI()
        auth = GradioAuth()

        @app.get("/")
        def index():
            return {"message": "Success"}

        with (
            patch.object(auth, "_get_user_from_headers", return_value=mock_user),
            patch.object(auth, "_is_authorised", return_value=True),
        ):
            auth.protect_app(app)
            client = TestClient(app)

            response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

            assert response.status_code == 200
            assert response.json()["message"] == "Success"

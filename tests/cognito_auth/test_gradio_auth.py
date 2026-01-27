import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognito_auth.gradio import GradioAuth


@pytest.fixture
def gradio_auth(auth_config_file):
    """Create GradioAuth instance with config"""
    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(auth_config_file)}, clear=True
    ):
        yield GradioAuth()


@pytest.fixture
def fastapi_app():
    """Create FastAPI app instance"""
    return FastAPI()


@pytest.fixture
def mock_gradio_request():
    """Create mock Gradio request object for standalone mode"""
    mock_request = MagicMock()
    mock_request.headers = {"X-Amzn-Oidc-Data": "token"}
    # Simulate no state.user (standalone mode)
    del mock_request.state.user
    return mock_request


# Tests for protect_app()


def test_protect_app_adds_middleware(gradio_auth, fastapi_app):
    """protect_app adds middleware to FastAPI app"""
    initial_middleware_count = len(fastapi_app.user_middleware)
    gradio_auth.protect_app(fastapi_app)

    # Verify middleware was added
    assert len(fastapi_app.user_middleware) > initial_middleware_count


def test_protect_app_middleware_redirects_unauthorised_user(
    gradio_auth, fastapi_app, mock_user_other
):
    """protect_app middleware redirects unauthorised users"""

    @fastapi_app.get("/")
    def index():
        return {"message": "Success"}

    with (
        patch.object(
            gradio_auth, "_get_user_from_headers", return_value=mock_user_other
        ),
        patch.object(gradio_auth, "_is_authorised", return_value=False),
    ):
        gradio_auth.protect_app(fastapi_app)
        client = TestClient(fastapi_app)

        response = client.get(
            "/",
            headers={"X-Amzn-Oidc-Data": "token"},
            follow_redirects=False,
        )

        # Should redirect
        assert response.status_code == 307
        assert gradio_auth.redirect_url in response.headers["location"]


# Tests for get_auth_user()


def test_get_auth_user_retrieves_from_request_state_when_protect_app_used(
    gradio_auth, mock_user_developer
):
    """get_auth_user retrieves user from request.state when protect_app used"""
    # Mock a Gradio request with state containing user
    mock_request = MagicMock()
    mock_request.state.user = mock_user_developer

    user = gradio_auth.get_auth_user(mock_request)
    assert user == mock_user_developer


def test_get_auth_user_validates_on_demand_for_standalone_gradio(
    gradio_auth, mock_gradio_request, mock_user_developer
):
    """get_auth_user validates on-demand for standalone Gradio"""
    with (
        patch.object(
            gradio_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(gradio_auth, "_is_authorised", return_value=True),
    ):
        user = gradio_auth.get_auth_user(mock_gradio_request)
        assert user == mock_user_developer


def test_get_auth_user_raises_permission_error_when_unauthorised(
    gradio_auth, mock_gradio_request, mock_user_other
):
    """get_auth_user raises PermissionError when user not authorised"""
    with (
        patch.object(
            gradio_auth, "_get_user_from_headers", return_value=mock_user_other
        ),
        patch.object(gradio_auth, "_is_authorised", return_value=False),
    ):
        with pytest.raises(PermissionError, match="Access denied"):
            gradio_auth.get_auth_user(mock_gradio_request)


def test_protect_app_allows_authorised_user(
    gradio_auth, fastapi_app, mock_user_developer
):
    """protect_app middleware allows authorised users through"""

    @fastapi_app.get("/")
    def index():
        return {"message": "Success"}

    with (
        patch.object(
            gradio_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(gradio_auth, "_is_authorised", return_value=True),
    ):
        gradio_auth.protect_app(fastapi_app)
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 200
        assert response.json()["message"] == "Success"

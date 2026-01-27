import os
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth


@pytest.fixture
def fastapi_auth(auth_config_file):
    """Create FastAPIAuth instance with config"""
    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(auth_config_file)}, clear=True
    ):
        yield FastAPIAuth()


@pytest.fixture
def fastapi_app():
    """Create FastAPI app instance"""
    return FastAPI()


# Tests for protect_app()


def test_protect_app_adds_middleware(fastapi_auth, fastapi_app):
    """protect_app adds middleware to FastAPI app"""
    initial_middleware_count = len(fastapi_app.user_middleware)
    fastapi_auth.protect_app(fastapi_app)

    # Verify middleware was added
    assert len(fastapi_app.user_middleware) > initial_middleware_count


def test_protect_app_middleware_redirects_unauthorised_user(
    fastapi_auth, fastapi_app, mock_user_other
):
    """protect_app middleware redirects unauthorised users"""

    @fastapi_app.get("/")
    def index():
        return {"message": "Success"}

    with (
        patch.object(
            fastapi_auth, "_get_user_from_headers", return_value=mock_user_other
        ),
        patch.object(fastapi_auth, "_is_authorised", return_value=False),
    ):
        fastapi_auth.protect_app(fastapi_app)
        client = TestClient(fastapi_app)

        response = client.get(
            "/",
            headers={"X-Amzn-Oidc-Data": "token"},
            follow_redirects=False,
        )

        # Should redirect
        assert response.status_code == 307  # FastAPI redirect status
        assert fastapi_auth.redirect_url in response.headers["location"]


# Tests for get_auth_user()


def test_get_auth_user_retrieves_from_request_state_when_protect_app_used(
    fastapi_auth, fastapi_app, mock_user_developer
):
    """get_auth_user retrieves user from request.state when protect_app used"""

    @fastapi_app.get("/")
    def index(user: User = Depends(fastapi_auth.get_auth_user)):  # noqa: B008
        return {"email": user.email}

    with (
        patch.object(
            fastapi_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(fastapi_auth, "_is_authorised", return_value=True),
    ):
        fastapi_auth.protect_app(fastapi_app)
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 200
        assert response.json()["email"] == mock_user_developer.email


def test_get_auth_user_validates_on_demand_without_protect_app(
    fastapi_auth, fastapi_app, mock_user_developer
):
    """get_auth_user validates on-demand when protect_app not used"""
    # Note: NOT calling protect_app()

    @fastapi_app.get("/")
    def index(user: User = Depends(fastapi_auth.get_auth_user)):  # noqa: B008
        return {"email": user.email}

    with (
        patch.object(
            fastapi_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(fastapi_auth, "_is_authorised", return_value=True),
    ):
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 200
        assert response.json()["email"] == mock_user_developer.email


def test_get_auth_user_raises_http_exception_when_unauthorised(
    fastapi_auth, fastapi_app, mock_user_other
):
    """get_auth_user raises HTTPException 403 when user not authorised"""

    @fastapi_app.get("/")
    def index(user: User = Depends(fastapi_auth.get_auth_user)):  # noqa: B008
        return {"email": user.email}

    with (
        patch.object(
            fastapi_auth, "_get_user_from_headers", return_value=mock_user_other
        ),
        patch.object(fastapi_auth, "_is_authorised", return_value=False),
    ):
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]


def test_get_auth_user_raises_http_exception_on_auth_failure(fastapi_auth, fastapi_app):
    """get_auth_user raises HTTPException 401 when authentication fails"""

    @fastapi_app.get("/")
    def index(user: User = Depends(fastapi_auth.get_auth_user)):  # noqa: B008
        return {"email": user.email}

    with patch.object(
        fastapi_auth, "_get_user_from_headers", side_effect=Exception("Auth failed")
    ):
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 401
        assert "Authentication failed" in response.json()["detail"]


def test_protect_app_allows_authorised_user(
    fastapi_auth, fastapi_app, mock_user_developer
):
    """protect_app middleware allows authorised users through"""

    @fastapi_app.get("/")
    def index():
        return {"message": "Success"}

    with (
        patch.object(
            fastapi_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(fastapi_auth, "_is_authorised", return_value=True),
    ):
        fastapi_auth.protect_app(fastapi_app)
        client = TestClient(fastapi_app)

        response = client.get("/", headers={"X-Amzn-Oidc-Data": "token"})

        assert response.status_code == 200
        assert response.json()["message"] == "Success"

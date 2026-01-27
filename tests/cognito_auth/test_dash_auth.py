import os
from unittest.mock import patch

import pytest
from dash import Dash
from flask import Flask, g

from cognito_auth.dash import DashAuth


@pytest.fixture
def dash_auth(auth_config_file):
    """Create DashAuth instance with config"""
    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(auth_config_file)}, clear=True
    ):
        yield DashAuth()


@pytest.fixture
def flask_app():
    """Create Flask app instance"""
    return Flask(__name__)


@pytest.fixture
def dash_app():
    """Create Dash app instance"""
    return Dash(__name__)


# Tests for protect_app()


def test_protect_app_with_dash_app(dash_auth, dash_app):
    """protect_app works with Dash app"""
    # Should not raise any errors
    dash_auth.protect_app(dash_app)

    # Verify the Flask app has before_request functions registered
    assert len(dash_app.server.before_request_funcs[None]) > 0


def test_protect_app_with_flask_app(dash_auth, flask_app):
    """protect_app works with Flask app"""
    # Should not raise any errors
    dash_auth.protect_app(flask_app)

    # Verify the Flask app has before_request functions registered
    assert len(flask_app.before_request_funcs[None]) > 0


# Tests for get_auth_user()


def test_get_auth_user_retrieves_from_g_when_protect_app_used(
    dash_auth, flask_app, mock_user_developer
):
    """get_auth_user retrieves user from g.user when protect_app was used"""
    dash_auth.protect_app(flask_app)

    # Simulate protect_app storing user in g
    with flask_app.test_request_context():
        g.user = mock_user_developer

        user = dash_auth.get_auth_user()
        assert user == mock_user_developer


def test_get_auth_user_validates_on_demand_without_protect_app(
    dash_auth, flask_app, mock_user_developer
):
    """get_auth_user validates on-demand when protect_app not used"""
    # Note: NOT calling protect_app()

    with flask_app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
        with (
            patch.object(
                dash_auth, "_get_user_from_headers", return_value=mock_user_developer
            ),
            patch.object(dash_auth, "_is_authorised", return_value=True),
        ):
            user = dash_auth.get_auth_user()
            assert user == mock_user_developer


def test_get_auth_user_raises_permission_error_when_unauthorised(
    dash_auth, flask_app, mock_user_other
):
    """get_auth_user raises PermissionError when user not authorised"""
    with flask_app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
        with (
            patch.object(
                dash_auth, "_get_user_from_headers", return_value=mock_user_other
            ),
            patch.object(dash_auth, "_is_authorised", return_value=False),
        ):
            with pytest.raises(PermissionError, match="Access denied"):
                dash_auth.get_auth_user()


# Tests for require_auth decorator


def test_require_auth_decorator_allows_authorised_user(
    dash_auth, flask_app, mock_user_developer
):
    """require_auth decorator allows authorised user through"""

    @dash_auth.require_auth
    def protected_route():
        return "Success"

    with flask_app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
        with (
            patch.object(
                dash_auth, "_get_user_from_headers", return_value=mock_user_developer
            ),
            patch.object(dash_auth, "_is_authorised", return_value=True),
        ):
            result = protected_route()
            assert result == "Success"
            # Verify user was stored in g
            assert g.user == mock_user_developer


def test_require_auth_decorator_redirects_unauthorised_user(
    dash_auth, flask_app, mock_user_other
):
    """require_auth decorator redirects unauthorised user"""

    @dash_auth.require_auth
    def protected_route():
        return "Success"

    with flask_app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
        with (
            patch.object(
                dash_auth, "_get_user_from_headers", return_value=mock_user_other
            ),
            patch.object(dash_auth, "_is_authorised", return_value=False),
        ):
            response = protected_route()
            # Should return a redirect response
            assert response.status_code == 302
            assert dash_auth.redirect_url in response.location


def test_require_auth_decorator_redirects_on_auth_failure(dash_auth, flask_app):
    """require_auth decorator redirects when authentication fails"""

    @dash_auth.require_auth
    def protected_route():
        return "Success"

    with flask_app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
        with patch.object(
            dash_auth, "_get_user_from_headers", side_effect=Exception("Auth failed")
        ):
            response = protected_route()
            # Should return a redirect response
            assert response.status_code == 302
            assert dash_auth.redirect_url in response.location

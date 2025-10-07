import os
from unittest.mock import patch

import pytest
from dash import Dash
from flask import Flask, g

from cognito_auth import Authorizer, User
from cognito_auth.dash import DashAuth


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authorizer.clear_config_cache()
    return


# Tests for protect_app()


def test_protect_app_with_dash_app(tmp_path):
    """protect_app works with Dash app"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        app = Dash(__name__)
        auth = DashAuth()

        # Should not raise any errors
        auth.protect_app(app)

        # Verify the Flask app has before_request functions registered
        assert len(app.server.before_request_funcs[None]) > 0


def test_protect_app_with_flask_app(tmp_path):
    """protect_app works with Flask app"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        app = Flask(__name__)
        auth = DashAuth()

        # Should not raise any errors
        auth.protect_app(app)

        # Verify the Flask app has before_request functions registered
        assert len(app.before_request_funcs[None]) > 0


# Tests for get_auth_user()


def test_get_auth_user_retrieves_from_g_when_protect_app_used(tmp_path):
    """get_auth_user retrieves user from g.user when protect_app was used"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        app = Flask(__name__)
        auth = DashAuth()
        auth.protect_app(app)

        # Simulate protect_app storing user in g
        with app.test_request_context():
            mock_user = User.create_mock(groups=["developers"])
            g.user = mock_user

            user = auth.get_auth_user()
            assert user == mock_user


def test_get_auth_user_validates_on_demand_without_protect_app(tmp_path):
    """get_auth_user validates on-demand when protect_app not used"""
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
        app = Flask(__name__)
        auth = DashAuth()
        # Note: NOT calling protect_app()

        with app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
            with (
                patch.object(auth, "_get_user_from_headers", return_value=mock_user),
                patch.object(auth, "_is_authorized", return_value=True),
            ):
                user = auth.get_auth_user()
                assert user == mock_user


def test_get_auth_user_raises_permission_error_when_unauthorized(tmp_path):
    """get_auth_user raises PermissionError when user not authorized"""
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
        app = Flask(__name__)
        auth = DashAuth()

        with app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
            with (
                patch.object(auth, "_get_user_from_headers", return_value=mock_user),
                patch.object(auth, "_is_authorized", return_value=False),
            ):
                with pytest.raises(PermissionError, match="Access denied"):
                    auth.get_auth_user()


# Tests for require_auth decorator


def test_require_auth_decorator_allows_authorized_user(tmp_path):
    """require_auth decorator allows authorized user through"""
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
        app = Flask(__name__)
        auth = DashAuth()

        @auth.require_auth
        def protected_route():
            return "Success"

        with app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
            with (
                patch.object(auth, "_get_user_from_headers", return_value=mock_user),
                patch.object(auth, "_is_authorized", return_value=True),
            ):
                result = protected_route()
                assert result == "Success"
                # Verify user was stored in g
                assert g.user == mock_user


def test_require_auth_decorator_redirects_unauthorized_user(tmp_path):
    """require_auth decorator redirects unauthorized user"""
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
        app = Flask(__name__)
        auth = DashAuth()

        @auth.require_auth
        def protected_route():
            return "Success"

        with app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
            with (
                patch.object(auth, "_get_user_from_headers", return_value=mock_user),
                patch.object(auth, "_is_authorized", return_value=False),
            ):
                response = protected_route()
                # Should return a redirect response
                assert response.status_code == 302
                assert auth.redirect_url in response.location


def test_require_auth_decorator_redirects_on_auth_failure(tmp_path):
    """require_auth decorator redirects when authentication fails"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )

    with (
        patch.dict(
            os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
        ),
    ):
        app = Flask(__name__)
        auth = DashAuth()

        @auth.require_auth
        def protected_route():
            return "Success"

        with app.test_request_context(headers={"X-Amzn-Oidc-Data": "token"}):
            with patch.object(
                auth, "_get_user_from_headers", side_effect=Exception("Auth failed")
            ):
                response = protected_route()
                # Should return a redirect response
                assert response.status_code == 302
                assert auth.redirect_url in response.location

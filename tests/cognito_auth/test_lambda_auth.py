import os
from unittest.mock import patch

import pytest

from cognito_auth.exceptions import MissingTokenError
from cognito_auth.lambda_auth import LambdaAuth


@pytest.fixture
def lambda_auth(auth_config_file):
    """Create LambdaAuth instance with config"""
    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(auth_config_file)}, clear=True
    ):
        yield LambdaAuth()


@pytest.fixture
def alb_event():
    """Create a minimal ALB Lambda event with OIDC headers"""
    return {
        "requestContext": {
            "elb": {
                "targetGroupArn": (
                    "arn:aws:elasticloadbalancing"
                    ":eu-west-2:123456789"
                    ":targetgroup/test/abc123"
                )
            }
        },
        "httpMethod": "GET",
        "path": "/",
        "queryStringParameters": {},
        "headers": {
            "x-amzn-oidc-data": "mock-oidc-token",
            "x-amzn-oidc-accesstoken": "mock-access-token",
            "host": "example.com",
        },
        "body": "",
        "isBase64Encoded": False,
    }


# Tests for get_auth_user()


def test_get_auth_user_returns_user(lambda_auth, alb_event, mock_user_developer):
    """get_auth_user returns authenticated and authorised user"""
    with (
        patch.object(
            lambda_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(lambda_auth, "_is_authorised", return_value=True),
    ):
        user = lambda_auth.get_auth_user(alb_event)

        assert user == mock_user_developer
        assert user.email == mock_user_developer.email


def test_get_auth_user_passes_headers_to_base(
    lambda_auth, alb_event, mock_user_developer
):
    """get_auth_user extracts headers from event and passes to _get_user_from_headers"""
    with (
        patch.object(
            lambda_auth, "_get_user_from_headers", return_value=mock_user_developer
        ) as mock_get_user,
        patch.object(lambda_auth, "_is_authorised", return_value=True),
    ):
        lambda_auth.get_auth_user(alb_event)

        mock_get_user.assert_called_once_with(alb_event["headers"])


def test_get_auth_user_raises_on_missing_headers(lambda_auth):
    """get_auth_user raises when OIDC headers are missing"""
    event = {
        "headers": {"host": "example.com"},
    }

    with pytest.raises(MissingTokenError):
        lambda_auth.get_auth_user(event)


def test_get_auth_user_raises_on_empty_event(lambda_auth):
    """get_auth_user raises when event has no headers key"""
    event = {}

    with pytest.raises(MissingTokenError):
        lambda_auth.get_auth_user(event)


def test_get_auth_user_raises_permission_error_when_unauthorised(
    lambda_auth, alb_event, mock_user_other
):
    """get_auth_user raises PermissionError when user not authorised"""
    with (
        patch.object(
            lambda_auth, "_get_user_from_headers", return_value=mock_user_other
        ),
        patch.object(lambda_auth, "_is_authorised", return_value=False),
    ):
        with pytest.raises(PermissionError, match="Access denied"):
            lambda_auth.get_auth_user(alb_event)


def test_get_auth_user_propagates_auth_exception(lambda_auth, alb_event):
    """get_auth_user propagates exceptions from token verification"""
    with patch.object(
        lambda_auth, "_get_user_from_headers", side_effect=Exception("Token invalid")
    ):
        with pytest.raises(Exception, match="Token invalid"):
            lambda_auth.get_auth_user(alb_event)


def test_get_auth_user_works_with_real_event_structure(
    lambda_auth, mock_user_developer
):
    """get_auth_user works with a realistic ALB event shape"""
    event = {
        "requestContext": {
            "elb": {
                "targetGroupArn": (
                    "arn:aws:elasticloadbalancing"
                    ":eu-west-2:992382722318"
                    ":targetgroup/test-proxy/2d8d8e1dd3e26a51"
                )
            }
        },
        "httpMethod": "GET",
        "path": "/404.html",
        "queryStringParameters": {},
        "headers": {
            "accept": "text/html",
            "host": "gds-idea.click",
            "x-amzn-oidc-accesstoken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
            "x-amzn-oidc-data": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9",
            "x-amzn-oidc-identity": "16f2c2a4-0071-70dd-3afa-20777368520f",
            "x-forwarded-for": "90.254.238.183",
            "x-forwarded-port": "443",
            "x-forwarded-proto": "https",
        },
        "body": "",
        "isBase64Encoded": True,
    }

    with (
        patch.object(
            lambda_auth, "_get_user_from_headers", return_value=mock_user_developer
        ),
        patch.object(lambda_auth, "_is_authorised", return_value=True),
    ):
        user = lambda_auth.get_auth_user(event)
        assert user == mock_user_developer


def test_dev_mode_returns_mock_user(auth_config_file):
    """Dev mode bypasses authentication and returns mock user"""
    with patch.dict(
        os.environ,
        {
            "COGNITO_AUTH_DEV_MODE": "true",
        },
        clear=True,
    ):
        auth = LambdaAuth(authoriser=None)
        event = {"headers": {}}

        user = auth.get_auth_user(event)

        assert user is not None
        assert user.email is not None

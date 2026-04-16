import json
import os
import time
import warnings
from unittest.mock import MagicMock, patch

import pytest

from cognito_auth import User
from cognito_auth.exceptions import MissingTokenError


@pytest.fixture
def mock_dev_config(tmp_path):
    """Fixture providing a temporary dev config file"""
    config = {
        "email": "fixture@example.com",
        "username": "fixture_user",
        "sub": "fixture-sub-123",
        "groups": ["fixture-group"],
    }
    config_file = tmp_path / "dev-mock-user.json"
    config_file.write_text(json.dumps(config))
    return tmp_path, config


@pytest.fixture
def suppress_warnings():
    """Fixture to suppress UserWarnings during tests"""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        yield


# Tests for User.create_mock()


def test_create_mock_with_defaults(suppress_warnings):
    """Create mock user with default values"""
    user = User.create_mock()

    assert user.email == "dev@example.com"
    assert user.sub.startswith("mock-")
    assert user.username == user.sub
    assert user.groups == []
    assert user.email_verified is True
    assert user.is_authenticated is True
    assert user.email_domain == "example.com"


def test_create_mock_with_custom_values(suppress_warnings):
    """Create mock user with custom values"""
    user = User.create_mock(
        email="test@company.com",
        sub="custom-sub-123",
        username="custom-username",
        groups=["admin", "users"],
    )

    assert user.email == "test@company.com"
    assert user.sub == "custom-sub-123"
    assert user.username == "custom-username"
    assert user.groups == ["admin", "users"]
    assert user.email_domain == "company.com"


def test_create_mock_raises_warning():
    """Create mock user raises appropriate warning"""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        User.create_mock()

        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "create_mock() is being used" in str(w[0].message)


def test_create_mock_with_extra_claims(suppress_warnings):
    """Create mock user with extra custom claims"""
    user = User.create_mock(
        email="test@example.com",
        custom_field="custom_value",
    )

    assert user.oidc_claims["custom_field"] == "custom_value"
    assert user.access_claims["custom_field"] == "custom_value"


def test_create_mock_loads_json_config(mock_dev_config, suppress_warnings):
    """Mock user loads values from JSON config"""
    tmp_path, config = mock_dev_config

    with patch("cognito_auth.user.Path.cwd", return_value=tmp_path):
        user = User.create_mock()

        assert user.email == config["email"]
        assert user.username == config["username"]
        assert user.sub == config["sub"]
        assert user.groups == config["groups"]


def test_create_mock_params_override_json(mock_dev_config, suppress_warnings):
    """Parameters override JSON config values"""
    tmp_path, config = mock_dev_config

    with patch("cognito_auth.user.Path.cwd", return_value=tmp_path):
        user = User.create_mock(
            email="override@example.com",
            groups=["override-group"],
        )

        assert user.email == "override@example.com"
        assert user.groups == ["override-group"]


def test_create_mock_uses_env_var_config_path(tmp_path, suppress_warnings):
    """Load config from custom path via env var"""
    config = {"email": "custom@example.com"}
    config_file = tmp_path / "custom-config.json"
    config_file.write_text(json.dumps(config))

    with patch.dict(os.environ, {"COGNITO_AUTH_DEV_CONFIG": str(config_file)}):
        user = User.create_mock()
        assert user.email == "custom@example.com"


def test_create_mock_handles_missing_json(suppress_warnings):
    """Missing JSON file falls back to defaults"""
    with patch("cognito_auth.user.Path.exists", return_value=False):
        user = User.create_mock()
        assert user.email == "dev@example.com"


def test_create_mock_handles_invalid_json(tmp_path):
    """Invalid JSON file warns and falls back to defaults"""
    config_file = tmp_path / "dev-mock-user.json"
    config_file.write_text("invalid json {{{")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        with patch("cognito_auth.user.Path.cwd", return_value=tmp_path):
            user = User.create_mock()

            # Should warn about failed load
            warning_messages = [str(warning.message) for warning in w]
            assert any("Failed to load dev config" in msg for msg in warning_messages)
            # Should still create user with defaults
            assert user.email == "dev@example.com"


# Tests for User properties


def test_user_email_domain_extraction(suppress_warnings):
    """Email domain is correctly extracted"""
    user = User.create_mock(email="user@company.co.uk")
    assert user.email_domain == "company.co.uk"


def test_user_email_domain_with_no_email(suppress_warnings):
    """Email domain returns empty string when email is empty"""
    # Create user then override email in claims to test the property
    user = User.create_mock()
    # Test that the property handles empty email correctly
    user._oidc_claims["email"] = ""
    assert user.email_domain == ""


def test_user_groups_empty_list(suppress_warnings):
    """Groups returns empty list when not set"""
    user = User.create_mock(groups=[])
    assert user.groups == []


def test_user_groups_populated(suppress_warnings):
    """Groups returns correct list"""
    user = User.create_mock(groups=["admin", "users", "developers"])
    assert user.groups == ["admin", "users", "developers"]


def test_user_is_in_returns_true(suppress_warnings):
    """is_in returns True when user belongs to group"""
    user = User.create_mock(groups=["developers", "users"])
    assert user.is_in("developers") is True


def test_user_is_in_returns_false(suppress_warnings):
    """is_in returns False when user does not belong to group"""
    user = User.create_mock(groups=["developers", "users"])
    assert user.is_in("admins") is False


def test_user_is_in_empty_groups(suppress_warnings):
    """is_in returns False when user has no groups"""
    user = User.create_mock(groups=[])
    assert user.is_in("developers") is False


def test_user_is_admin_true(suppress_warnings):
    """is_admin returns True when user is in gds-idea group"""
    user = User.create_mock(groups=["gds-idea", "users"])
    assert user.is_admin is True


def test_user_is_admin_false(suppress_warnings):
    """is_admin returns False when user is not in gds-idea group"""
    user = User.create_mock(groups=["admin", "users", "developers"])
    assert user.is_admin is False


def test_user_is_admin_empty_groups(suppress_warnings):
    """is_admin returns False when groups is empty"""
    user = User.create_mock(groups=[])
    assert user.is_admin is False


def test_user_is_admin_true_for_app_admin(suppress_warnings):
    """is_admin returns True when user is an app admin"""
    user = User.create_mock(groups=["dsit"])
    user.is_app_admin = True
    assert user.is_admin is True


def test_user_is_gds_idea_true(suppress_warnings):
    """is_gds_idea returns True when user is in gds-idea group"""
    user = User.create_mock(groups=["gds-idea", "users"])
    assert user.is_gds_idea is True


def test_user_is_gds_idea_false(suppress_warnings):
    """is_gds_idea returns False when user is not in gds-idea group"""
    user = User.create_mock(groups=["developers"])
    assert user.is_gds_idea is False


def test_user_is_app_admin_defaults_false(suppress_warnings):
    """is_app_admin defaults to False"""
    user = User.create_mock(groups=["developers"])
    assert user.is_app_admin is False


def test_user_is_app_admin_settable(suppress_warnings):
    """is_app_admin can be set to True"""
    user = User.create_mock(groups=["developers"])
    user.is_app_admin = True
    assert user.is_app_admin is True


def test_user_exp_in_future(suppress_warnings):
    """Expiration is in the future"""
    user = User.create_mock()
    assert user.exp is not None
    assert user.exp.timestamp() > time.time()


def test_user_issuer_contains_region(suppress_warnings):
    """Issuer contains the correct region"""
    user = User.create_mock(region="us-east-1")
    assert "us-east-1" in user.issuer
    assert "cognito-idp" in user.issuer


def test_user_oidc_claims_returns_copy(suppress_warnings):
    """oidc_claims returns a copy, not reference"""
    user = User.create_mock()
    claims1 = user.oidc_claims
    claims2 = user.oidc_claims

    assert claims1 == claims2
    assert claims1 is not claims2


def test_user_access_claims_returns_copy(suppress_warnings):
    """access_claims returns a copy, not reference"""
    user = User.create_mock()
    claims1 = user.access_claims
    claims2 = user.access_claims

    assert claims1 == claims2
    assert claims1 is not claims2


def test_user_email_verified_true(suppress_warnings):
    """email_verified returns True when set"""
    user = User.create_mock(email_verified=True)
    assert user.email_verified is True


def test_user_email_verified_false(suppress_warnings):
    """email_verified returns False when set"""
    user = User.create_mock(email_verified=False)
    assert user.email_verified is False


# Tests for User string representation


def test_user_str_returns_email(suppress_warnings):
    """__str__ returns email address"""
    user = User.create_mock(email="test@example.com")
    assert str(user) == "test@example.com"


def test_user_repr_includes_key_fields(suppress_warnings):
    """__repr__ includes name, email, and sub"""
    user = User.create_mock(
        email="test@example.com",
        name="Test User",
        sub="test-sub",
    )
    repr_str = repr(user)
    assert "Test User" in repr_str
    assert "test@example.com" in repr_str
    assert "test-sub" in repr_str


# Tests for User name properties


def test_user_name_property(suppress_warnings):
    """name returns user's full name"""
    user = User.create_mock(name="David Gillespie")
    assert user.name == "David Gillespie"


def test_user_given_name_property(suppress_warnings):
    """given_name returns user's first name"""
    user = User.create_mock(given_name="David")
    assert user.given_name == "David"


def test_user_family_name_property(suppress_warnings):
    """family_name returns user's last name"""
    user = User.create_mock(family_name="Gillespie")
    assert user.family_name == "Gillespie"


def test_user_name_defaults_when_claim_missing(suppress_warnings):
    """Name properties return empty string when claims are absent"""
    user = User.create_mock()
    # Remove name claims to simulate missing OIDC claims
    user._oidc_claims.pop("name", None)
    user._oidc_claims.pop("given_name", None)
    user._oidc_claims.pop("family_name", None)

    assert user.name == ""
    assert user.given_name == ""
    assert user.family_name == ""


def test_create_mock_name_defaults(suppress_warnings):
    """Mock user has sensible name defaults"""
    user = User.create_mock()
    assert user.given_name == "Dev"
    assert user.family_name == "User"
    assert user.name == "Dev User"


def test_create_mock_custom_name_fields(suppress_warnings):
    """Mock user accepts custom name values"""
    user = User.create_mock(
        name="David Gillespie",
        given_name="David",
        family_name="Gillespie",
    )
    assert user.name == "David Gillespie"
    assert user.given_name == "David"
    assert user.family_name == "Gillespie"


def test_create_mock_name_auto_composed(suppress_warnings):
    """Mock user auto-composes name from given_name and family_name"""
    user = User.create_mock(given_name="Jane", family_name="Smith")
    assert user.name == "Jane Smith"


def test_create_mock_name_from_json_config(mock_dev_config, suppress_warnings):
    """Mock user loads name fields from JSON config"""
    tmp_path, config = mock_dev_config
    # Add name fields to the config file
    config["name"] = "Fixture User"
    config["given_name"] = "Fixture"
    config["family_name"] = "User"
    config_file = tmp_path / "dev-mock-user.json"
    config_file.write_text(json.dumps(config))

    with patch("cognito_auth.user.Path.cwd", return_value=tmp_path):
        user = User.create_mock()
        assert user.name == "Fixture User"
        assert user.given_name == "Fixture"
        assert user.family_name == "User"


# Tests for User initialization with headers


def test_user_init_missing_oidc_header_raises_error():
    """Missing OIDC header raises MissingTokenError"""
    with pytest.raises(MissingTokenError, match="x-amzn-oidc-data"):
        User(
            oidc_data_header=None,
            access_token_header="fake-token",
            region="eu-west-2",
        )


def test_user_init_missing_access_header_raises_error():
    """Missing access token header raises MissingTokenError"""
    with pytest.raises(MissingTokenError, match="x-amzn-oidc-accesstoken"):
        User(
            oidc_data_header="fake-token",
            access_token_header=None,
            region="eu-west-2",
        )


def test_user_init_with_mocked_verification():
    """User initialization with mocked token verification"""
    mock_oidc_claims = {
        "sub": "test-sub",
        "email": "test@example.com",
        "username": "test-username",
        "email_verified": "true",
        "exp": int(time.time()) + 3600,
    }

    mock_access_claims = {
        "sub": "test-sub",
        "username": "test-username",
        "cognito:groups": ["admin"],
    }

    with patch("cognito_auth.user.TokenVerifier") as mock_verifier_class:
        mock_verifier = MagicMock()
        mock_verifier.verify_alb_token.return_value = mock_oidc_claims
        mock_verifier.verify_cognito_token.return_value = mock_access_claims
        mock_verifier_class.return_value = mock_verifier

        user = User(
            oidc_data_header="fake-oidc-token",
            access_token_header="fake-access-token",
            region="eu-west-2",
            verify_tokens=True,
        )

        assert user.email == "test@example.com"
        assert user.sub == "test-sub"
        assert user.username == "test-username"
        assert user.groups == ["admin"]
        assert user.is_authenticated is True

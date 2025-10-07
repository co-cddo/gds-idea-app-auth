import json
import os
import warnings
from unittest.mock import MagicMock, patch

import pytest

from cognito_auth import Authoriser, User
from cognito_auth.authoriser import EmailRule, GroupRule


@pytest.fixture
def suppress_warnings():
    """Fixture to suppress UserWarnings during tests"""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        yield


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authoriser.clear_config_cache()
    return


@pytest.fixture
def mock_user(suppress_warnings):
    """Fixture providing a mock user with groups"""
    return User.create_mock(
        email="test@example.com",
        groups=["developers", "users"],
    )


@pytest.fixture
def mock_admin_user(suppress_warnings):
    """Fixture providing a mock admin user"""
    return User.create_mock(
        email="admin@example.com",
        groups=["admins"],
    )


@pytest.fixture
def mock_user_no_groups(suppress_warnings):
    """Fixture providing a mock user with no groups"""
    return User.create_mock(
        email="nogroups@example.com",
        groups=[],
    )


# Tests for GroupRule


def test_group_rule_allows_user_in_group(mock_user):
    """User in allowed group is authorised"""
    rule = GroupRule({"developers"})
    assert rule.is_allowed(mock_user) is True


def test_group_rule_allows_user_with_multiple_groups(mock_user):
    """User with one of multiple allowed groups is authorised"""
    rule = GroupRule({"developers", "admins"})
    assert rule.is_allowed(mock_user) is True


def test_group_rule_denies_user_not_in_group(mock_user):
    """User not in allowed group is denied"""
    rule = GroupRule({"admins"})
    assert rule.is_allowed(mock_user) is False


def test_group_rule_denies_user_with_no_groups(mock_user_no_groups):
    """User with no groups is denied"""
    rule = GroupRule({"developers"})
    assert rule.is_allowed(mock_user_no_groups) is False


def test_group_rule_with_empty_allowed_groups(mock_user):
    """Rule with empty allowed groups denies all users"""
    rule = GroupRule(set())
    assert rule.is_allowed(mock_user) is False


# Tests for EmailRule


def test_email_rule_allows_matching_email(mock_user):
    """User with matching email is authorised"""
    rule = EmailRule({"test@example.com"})
    assert rule.is_allowed(mock_user) is True


def test_email_rule_allows_user_in_list(mock_user):
    """User with email in list is authorised"""
    rule = EmailRule({"test@example.com", "other@example.com"})
    assert rule.is_allowed(mock_user) is True


def test_email_rule_denies_non_matching_email(mock_user):
    """User with non-matching email is denied"""
    rule = EmailRule({"admin@example.com"})
    assert rule.is_allowed(mock_user) is False


def test_email_rule_with_empty_allowed_emails(mock_user):
    """Rule with empty allowed emails denies all users"""
    rule = EmailRule(set())
    assert rule.is_allowed(mock_user) is False


# Tests for Authoriser with single rules


def test_authoriser_with_single_group_rule_allows(mock_user):
    """Authoriser with group rule allows matching user"""
    rule = GroupRule({"developers"})
    authoriser = Authoriser([rule])
    assert authoriser.is_authorised(mock_user) is True


def test_authoriser_with_single_group_rule_denies(mock_user):
    """Authoriser with group rule denies non-matching user"""
    rule = GroupRule({"admins"})
    authoriser = Authoriser([rule])
    assert authoriser.is_authorised(mock_user) is False


def test_authoriser_with_single_email_rule_allows(mock_user):
    """Authoriser with email rule allows matching user"""
    rule = EmailRule({"test@example.com"})
    authoriser = Authoriser([rule])
    assert authoriser.is_authorised(mock_user) is True


def test_authoriser_with_single_email_rule_denies(mock_user):
    """Authoriser with email rule denies non-matching user"""
    rule = EmailRule({"other@example.com"})
    authoriser = Authoriser([rule])
    assert authoriser.is_authorised(mock_user) is False


# Tests for Authoriser with multiple rules (OR logic)


def test_authoriser_or_logic_allows_when_one_rule_passes(mock_user):
    """With OR logic, user passes if any rule matches"""
    rules = [
        GroupRule({"admins"}),  # Doesn't match
        EmailRule({"test@example.com"}),  # Matches
    ]
    authoriser = Authoriser(rules, require_all=False)
    assert authoriser.is_authorised(mock_user) is True


def test_authoriser_or_logic_denies_when_no_rules_pass(mock_user):
    """With OR logic, user denied if no rules match"""
    rules = [
        GroupRule({"admins"}),  # Doesn't match
        EmailRule({"other@example.com"}),  # Doesn't match
    ]
    authoriser = Authoriser(rules, require_all=False)
    assert authoriser.is_authorised(mock_user) is False


def test_authoriser_or_logic_allows_when_all_rules_pass(mock_user):
    """With OR logic, user passes if all rules match"""
    rules = [
        GroupRule({"developers"}),  # Matches
        EmailRule({"test@example.com"}),  # Matches
    ]
    authoriser = Authoriser(rules, require_all=False)
    assert authoriser.is_authorised(mock_user) is True


# Tests for Authoriser with multiple rules (AND logic)


def test_authoriser_and_logic_allows_when_all_rules_pass(mock_user):
    """With AND logic, user passes only if all rules match"""
    rules = [
        GroupRule({"developers"}),  # Matches
        EmailRule({"test@example.com"}),  # Matches
    ]
    authoriser = Authoriser(rules, require_all=True)
    assert authoriser.is_authorised(mock_user) is True


def test_authoriser_and_logic_denies_when_one_rule_fails(mock_user):
    """With AND logic, user denied if any rule fails"""
    rules = [
        GroupRule({"developers"}),  # Matches
        EmailRule({"other@example.com"}),  # Doesn't match
    ]
    authoriser = Authoriser(rules, require_all=True)
    assert authoriser.is_authorised(mock_user) is False


def test_authoriser_and_logic_denies_when_all_rules_fail(mock_user):
    """With AND logic, user denied if all rules fail"""
    rules = [
        GroupRule({"admins"}),  # Doesn't match
        EmailRule({"other@example.com"}),  # Doesn't match
    ]
    authoriser = Authoriser(rules, require_all=True)
    assert authoriser.is_authorised(mock_user) is False


# Tests for Authoriser with no rules


def test_authoriser_with_no_rules_allows_authenticated_user(mock_user):
    """Authoriser with no rules allows any authenticated user"""
    authoriser = Authoriser([])
    assert authoriser.is_authorised(mock_user) is True


def test_authoriser_with_empty_rules_allows(mock_user):
    """Empty rules list allows any authenticated user"""
    authoriser = Authoriser([], require_all=False)
    assert authoriser.is_authorised(mock_user) is True


# Tests for Authoriser.from_lists()


def test_from_lists_creates_authoriser_with_groups():
    """from_lists creates authoriser with group rules"""
    authoriser = Authoriser.from_lists(allowed_groups=["developers", "admins"])
    assert len(authoriser.rules) == 1
    assert isinstance(authoriser.rules[0], GroupRule)


def test_from_lists_creates_authoriser_with_users():
    """from_lists creates authoriser with email rules"""
    authoriser = Authoriser.from_lists(allowed_users=["test@example.com"])
    assert len(authoriser.rules) == 1
    assert isinstance(authoriser.rules[0], EmailRule)


def test_from_lists_creates_authoriser_with_both(mock_user):
    """from_lists creates authoriser with both rule types"""
    authoriser = Authoriser.from_lists(
        allowed_groups=["developers"],
        allowed_users=["admin@example.com"],
    )
    assert len(authoriser.rules) == 2
    # Should use OR logic by default
    assert authoriser.is_authorised(mock_user) is True


def test_from_lists_respects_require_all_flag(mock_user):
    """from_lists respects require_all flag"""
    authoriser = Authoriser.from_lists(
        allowed_groups=["developers"],
        allowed_users=["other@example.com"],
        require_all=True,
    )
    # User is in developers group but email doesn't match
    assert authoriser.is_authorised(mock_user) is False


def test_from_lists_with_no_params_creates_empty_authoriser():
    """from_lists with no parameters creates authoriser with no rules"""
    authoriser = Authoriser.from_lists()
    assert len(authoriser.rules) == 0


def test_from_lists_with_none_params_creates_empty_authoriser():
    """from_lists with None parameters creates authoriser with no rules"""
    authoriser = Authoriser.from_lists(
        allowed_groups=None,
        allowed_users=None,
    )
    assert len(authoriser.rules) == 0


# Integration tests with multiple users


def test_authoriser_allows_different_users_with_or_logic(
    mock_user, mock_admin_user, suppress_warnings
):
    """OR logic allows users matching different rules"""
    authoriser = Authoriser.from_lists(
        allowed_groups=["developers"],
        allowed_users=["admin@example.com"],
        require_all=False,
    )
    # mock_user matches group rule
    assert authoriser.is_authorised(mock_user) is True
    # mock_admin_user matches email rule
    assert authoriser.is_authorised(mock_admin_user) is True


def test_authoriser_requires_both_rules_with_and_logic(
    mock_user, mock_admin_user, suppress_warnings
):
    """AND logic requires all rules to pass"""
    authoriser = Authoriser.from_lists(
        allowed_groups=["developers"],
        allowed_users=["test@example.com"],
        require_all=True,
    )
    # mock_user matches both rules
    assert authoriser.is_authorised(mock_user) is True
    # mock_admin_user only matches neither rule
    assert authoriser.is_authorised(mock_admin_user) is False


def test_authoriser_denies_unauthenticated_user(suppress_warnings):
    """Authoriser denies unauthenticated users regardless of rules"""
    user = User.create_mock(email="test@example.com", groups=["developers"])
    # Manually set authenticated to False
    user._is_authenticated = False

    authoriser = Authoriser.from_lists(allowed_groups=["developers"])
    assert authoriser.is_authorised(user) is False


# Tests for Authoriser.from_config()


def test_from_config_loads_from_file(tmp_path):
    """from_config loads authorisation from local file"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["admin@example.com"],
        "require_all": False
    }))

    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}):
        authoriser = Authoriser.from_config()
        assert len(authoriser.rules) == 2
        assert authoriser.require_all is False


def test_from_config_validates_emails(tmp_path):
    """from_config validates email addresses"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["invalid-email"],
        "require_all": False
    }))

    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}):
        with pytest.raises(Exception, match="email address"):
            Authoriser.from_config()


def test_from_config_requires_at_least_one_rule(tmp_path):
    """from_config requires at least one authorisation rule"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({"require_all": False}))

    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}):
        with pytest.raises(ValueError, match="at least one of"):
            Authoriser.from_config()


def test_from_config_raises_without_env_vars():
    """from_config raises error if no env vars set"""
    with patch.dict(
        os.environ,
        {},
        clear=True
    ):
        with pytest.raises(ValueError, match="Must set either"):
            Authoriser.from_config()


def test_from_config_file_not_found():
    """from_config raises error if file doesn't exist"""
    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": "/nonexistent/file.json"}):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            Authoriser.from_config()


def test_from_config_invalid_json(tmp_path):
    """from_config raises error for invalid JSON"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text("invalid json {{{")

    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}):
        with pytest.raises(ValueError, match="Invalid JSON"):
            Authoriser.from_config()


def test_from_config_aws_secrets(mock_user, suppress_warnings):
    """from_config loads from AWS Secrets Manager"""
    mock_config = {
        "allowed_groups": ["developers"],
        "allowed_users": ["admin@example.com"],
        "require_all": False
    }

    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps(mock_config)
    }

    # Patch boto3.client at the point where it's called
    with patch("boto3.client", return_value=mock_client) as mock_boto3_client:
        with patch.dict(
            os.environ,
            {"COGNITO_AUTH_SECRET_NAME": "my-app/auth-config"},
            clear=True
        ):
            authoriser = Authoriser.from_config()

            assert len(authoriser.rules) == 2
            mock_boto3_client.assert_called_once_with("secretsmanager")
            mock_client.get_secret_value.assert_called_once_with(
                SecretId="my-app/auth-config"
            )


def test_from_config_respects_require_all(tmp_path):
    """from_config respects require_all flag"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["admin@example.com"],
        "require_all": True
    }))

    with patch.dict(os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}):
        authoriser = Authoriser.from_config()
        assert authoriser.require_all is True


# Tests for TTL caching


def test_from_config_caches_result(tmp_path):
    """from_config caches result and doesn't reload within TTL"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["user@example.com"],
        "require_all": False
    }))

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        # First call
        authoriser1 = Authoriser.from_config()

        # Second call should return same cached instance
        authoriser2 = Authoriser.from_config()

        # Should be the exact same object (cached)
        assert authoriser1 is authoriser2


def test_clear_config_cache_forces_reload(tmp_path):
    """clear_config_cache forces immediate reload"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["user@example.com"],
        "require_all": False
    }))

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        # First call
        authoriser1 = Authoriser.from_config()

        # Clear cache
        Authoriser.clear_config_cache()

        # Second call should create new instance
        authoriser2 = Authoriser.from_config()

        # Should be different objects
        assert authoriser1 is not authoriser2


def test_from_config_cache_with_file_change(tmp_path):
    """Config reload picks up changes after cache clear"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(json.dumps({
        "allowed_groups": ["developers"],
        "allowed_users": ["user@example.com"],
        "require_all": False
    }))

    with patch.dict(
        os.environ, {"COGNITO_AUTH_CONFIG_PATH": str(config_file)}, clear=True
    ):
        # First call
        authoriser1 = Authoriser.from_config()
        assert len(authoriser1.rules) == 2

        # Update config file
        config_file.write_text(json.dumps({
            "allowed_groups": ["admins", "developers", "users"],
            "allowed_users": ["user@example.com"],
            "require_all": False
        }))

        # Without clearing cache, should still get old config
        authoriser2 = Authoriser.from_config()
        assert authoriser1 is authoriser2

        # After clearing cache, should get new config
        Authoriser.clear_config_cache()
        authoriser3 = Authoriser.from_config()
        assert authoriser1 is not authoriser3

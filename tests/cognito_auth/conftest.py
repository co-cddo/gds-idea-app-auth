import pytest

from cognito_auth import Authoriser, User


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Automatically clear config cache before each test"""
    Authoriser.clear_config_cache()
    return


@pytest.fixture
def auth_config_file(tmp_path):
    """Create auth config file"""
    config_file = tmp_path / "auth-config.json"
    config_file.write_text(
        '{"allowed_groups": ["developers"], "allowed_users": [], "require_all": false}'
    )
    return config_file


@pytest.fixture
def mock_user_developer():
    """Create mock user in developers group"""
    return User.create_mock(groups=["developers"])


@pytest.fixture
def mock_user_other():
    """Create mock user in other-group"""
    return User.create_mock(groups=["other-group"])

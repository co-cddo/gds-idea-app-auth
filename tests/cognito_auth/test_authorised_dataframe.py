"""Tests for AuthorisedDataFrame."""

import warnings

import pytest

from cognito_auth import User
from cognito_auth.df import AuthorisedDataFrame

DOMAIN_MAPPING = {
    "cabinetoffice.gov.uk": ["Cabinet Office"],
    "digital.cabinet-office.gov.uk": ["Cabinet Office"],
    "homeoffice.gov.uk": ["Home Office"],
    "hmrc.gov.uk": ["HMRC"],
}


@pytest.fixture
def suppress_warnings():
    """Suppress UserWarnings from User.create_mock()."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        yield


@pytest.fixture
def cabinet_office_user(suppress_warnings):
    return User.create_mock(email="dev@cabinetoffice.gov.uk", groups=[])


@pytest.fixture
def home_office_user(suppress_warnings):
    return User.create_mock(email="dev@homeoffice.gov.uk", groups=[])


@pytest.fixture
def admin_user(suppress_warnings):
    return User.create_mock(email="admin@cabinetoffice.gov.uk", groups=["gds-idea"])


@pytest.fixture
def unmapped_user(suppress_warnings):
    return User.create_mock(email="someone@unknown.gov.uk", groups=[])


# ---------------------------------------------------------------------------
# _resolve() tests
# ---------------------------------------------------------------------------


class TestResolve:
    """Tests for AuthorisedDataFrame._resolve() static method."""

    def test_mapped_domain_returns_departments(self, cabinet_office_user):
        result = AuthorisedDataFrame._resolve(cabinet_office_user, DOMAIN_MAPPING)
        assert result == ["Cabinet Office"]

    def test_different_domain_returns_different_departments(self, home_office_user):
        result = AuthorisedDataFrame._resolve(home_office_user, DOMAIN_MAPPING)
        assert result == ["Home Office"]

    def test_unmapped_domain_returns_none(self, unmapped_user):
        result = AuthorisedDataFrame._resolve(unmapped_user, DOMAIN_MAPPING)
        assert result is None

    def test_admin_gets_all_departments_sorted(self, admin_user):
        result = AuthorisedDataFrame._resolve(admin_user, DOMAIN_MAPPING)
        assert result == ["Cabinet Office", "HMRC", "Home Office"]

    def test_multiple_domains_map_to_same_department(self, suppress_warnings):
        """digital.cabinet-office.gov.uk also maps to Cabinet Office."""
        user = User.create_mock(email="dev@digital.cabinet-office.gov.uk", groups=[])
        result = AuthorisedDataFrame._resolve(user, DOMAIN_MAPPING)
        assert result == ["Cabinet Office"]

    def test_domain_mapping_with_multiple_departments(self, suppress_warnings):
        """A single domain can map to multiple departments."""
        multi_mapping = {
            "cabinetoffice.gov.uk": ["Cabinet Office", "CDDO"],
        }
        user = User.create_mock(email="dev@cabinetoffice.gov.uk", groups=[])
        result = AuthorisedDataFrame._resolve(user, multi_mapping)
        assert result == ["Cabinet Office", "CDDO"]

    def test_empty_mapping_returns_none(self, cabinet_office_user):
        result = AuthorisedDataFrame._resolve(cabinet_office_user, {})
        assert result is None

    def test_admin_with_empty_mapping_returns_empty_list(self, admin_user):
        result = AuthorisedDataFrame._resolve(admin_user, {})
        assert result == []

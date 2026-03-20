"""Tests for AuthorisedDataFrame."""

import warnings

import pandas as pd
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


@pytest.fixture
def sample_df():
    return pd.DataFrame(
        {
            "department": [
                "Cabinet Office",
                "Cabinet Office",
                "Home Office",
                "HMRC",
            ],
            "project": ["Project A", "Project B", "Project C", "Project D"],
            "budget": [100, 200, 300, 400],
        }
    )


@pytest.fixture
def segments(sample_df):
    return dict(tuple(sample_df.groupby("department")))


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


# ---------------------------------------------------------------------------
# __init__ / filtering tests
# ---------------------------------------------------------------------------


class TestFiltering:
    """Tests for AuthorisedDataFrame construction and row-level filtering."""

    def test_single_department_user_sees_only_their_rows(
        self, segments, cabinet_office_user
    ):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        assert len(secure.df) == 2
        assert set(secure.df["department"]) == {"Cabinet Office"}

    def test_different_department_user_sees_different_rows(
        self, segments, home_office_user
    ):
        secure = AuthorisedDataFrame(segments, home_office_user, DOMAIN_MAPPING)
        assert len(secure.df) == 1
        assert set(secure.df["department"]) == {"Home Office"}

    def test_admin_sees_all_rows(self, segments, admin_user):
        secure = AuthorisedDataFrame(segments, admin_user, DOMAIN_MAPPING)
        assert len(secure.df) == 4

    def test_unmapped_user_gets_empty_dataframe(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        assert len(secure.df) == 0

    def test_unmapped_user_preserves_columns(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        assert list(secure.df.columns) == ["department", "project", "budget"]

    def test_has_access_true_for_mapped_user(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        assert secure.has_access is True

    def test_has_access_false_for_unmapped_user(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        assert secure.has_access is False

    def test_user_property_returns_original_user(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        assert secure.user is cabinet_office_user

    def test_departments_property(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        assert secure.departments == ["Cabinet Office"]

    def test_departments_none_for_unmapped_user(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        assert secure.departments is None

    def test_empty_segments_returns_empty_dataframe(self, cabinet_office_user):
        secure = AuthorisedDataFrame({}, cabinet_office_user, DOMAIN_MAPPING)
        assert len(secure.df) == 0

    def test_department_not_in_segments(self, suppress_warnings):
        """User maps to a department that has no rows in the data."""
        segments = {
            "Home Office": pd.DataFrame({"department": ["Home Office"], "x": [1]}),
        }
        user = User.create_mock(email="dev@hmrc.gov.uk", groups=[])
        secure = AuthorisedDataFrame(segments, user, DOMAIN_MAPPING)
        assert len(secure.df) == 0
        assert secure.has_access is True  # they have access, just no data


# ---------------------------------------------------------------------------
# to_store() tests
# ---------------------------------------------------------------------------


class TestToStore:
    """Tests for AuthorisedDataFrame.to_store() serialisation."""

    def test_returns_correct_keys(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        store = secure.to_store()
        assert set(store.keys()) == {
            "records",
            "user_name",
            "user_email",
            "departments",
            "has_access",
        }

    def test_records_match_filtered_data(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        store = secure.to_store()
        assert store["records"] == secure.df.to_dict("records")
        assert len(store["records"]) == 2

    def test_includes_user_context(self, segments, cabinet_office_user):
        secure = AuthorisedDataFrame(segments, cabinet_office_user, DOMAIN_MAPPING)
        store = secure.to_store()
        assert store["user_name"] == cabinet_office_user.name
        assert store["user_email"] == cabinet_office_user.email
        assert store["departments"] == ["Cabinet Office"]
        assert store["has_access"] is True

    def test_no_access_returns_empty_records(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        store = secure.to_store()
        assert store["records"] == []

    def test_no_access_has_access_false(self, segments, unmapped_user):
        secure = AuthorisedDataFrame(segments, unmapped_user, DOMAIN_MAPPING)
        store = secure.to_store()
        assert store["has_access"] is False
        assert store["departments"] is None


# ---------------------------------------------------------------------------
# from_dataframe() tests
# ---------------------------------------------------------------------------


class TestFromDataFrame:
    """Tests for AuthorisedDataFrame.from_dataframe() convenience constructor."""

    def test_produces_same_result_as_presegmented(
        self, sample_df, segments, cabinet_office_user
    ):
        from_segments = AuthorisedDataFrame(
            segments, cabinet_office_user, DOMAIN_MAPPING
        )
        from_df = AuthorisedDataFrame.from_dataframe(
            sample_df, "department", cabinet_office_user, DOMAIN_MAPPING
        )
        pd.testing.assert_frame_equal(
            from_segments.df.reset_index(drop=True),
            from_df.df.reset_index(drop=True),
        )

    def test_with_different_column_name(self, suppress_warnings):
        """Works with any column name, not just 'department'."""
        df = pd.DataFrame(
            {
                "org": ["Cabinet Office", "Home Office"],
                "value": [10, 20],
            }
        )
        user = User.create_mock(email="dev@cabinetoffice.gov.uk", groups=[])
        secure = AuthorisedDataFrame.from_dataframe(df, "org", user, DOMAIN_MAPPING)
        assert len(secure.df) == 1
        assert secure.df.iloc[0]["org"] == "Cabinet Office"


# ---------------------------------------------------------------------------
# DataModel pattern tests
# ---------------------------------------------------------------------------


class TestDataModelPattern:
    """Tests demonstrating the DataModel usage pattern with multiple DataFrames.

    This shows how an app with multiple data sources would use
    AuthorisedDataFrame -- one wrapper per source DataFrame, same user,
    same mapping.
    """

    def test_multiple_dataframes_same_user(self, cabinet_office_user):
        """Two DataFrames filtered for the same user."""
        spending_df = pd.DataFrame(
            {
                "department": ["Cabinet Office", "Home Office"],
                "budget": [100, 200],
            }
        )
        forecast_df = pd.DataFrame(
            {
                "department": ["Cabinet Office", "Home Office", "HMRC"],
                "forecast": [150, 250, 350],
            }
        )
        spending_segments = dict(tuple(spending_df.groupby("department")))
        forecast_segments = dict(tuple(forecast_df.groupby("department")))

        secure_spending = AuthorisedDataFrame(
            spending_segments, cabinet_office_user, DOMAIN_MAPPING
        )
        secure_forecast = AuthorisedDataFrame(
            forecast_segments, cabinet_office_user, DOMAIN_MAPPING
        )

        assert len(secure_spending.df) == 1
        assert len(secure_forecast.df) == 1
        assert secure_spending.df.iloc[0]["budget"] == 100
        assert secure_forecast.df.iloc[0]["forecast"] == 150

    def test_different_auth_columns(self, cabinet_office_user):
        """DataFrames can use different column names for department."""
        df_short = pd.DataFrame(
            {
                "dept": ["Cabinet Office", "Home Office"],
                "x": [1, 2],
            }
        )
        df_long = pd.DataFrame(
            {
                "organisation": ["Cabinet Office", "HMRC"],
                "y": [3, 4],
            }
        )

        secure_short = AuthorisedDataFrame.from_dataframe(
            df_short, "dept", cabinet_office_user, DOMAIN_MAPPING
        )
        secure_long = AuthorisedDataFrame.from_dataframe(
            df_long, "organisation", cabinet_office_user, DOMAIN_MAPPING
        )

        assert len(secure_short.df) == 1
        assert len(secure_long.df) == 1
        assert secure_short.df.iloc[0]["x"] == 1
        assert secure_long.df.iloc[0]["y"] == 3

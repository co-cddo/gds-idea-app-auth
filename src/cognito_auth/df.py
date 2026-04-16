"""
AuthorisedDataFrame: Row-level security for pandas DataFrames.

Provides a DataFrame wrapper that enforces department-based filtering
based on a User's identity. Requires the [df] extra:

    pip install cognito-auth[df]

Usage:
    from cognito_auth.df import AuthorisedDataFrame

    # Startup -- segment once
    spending = AuthorisedDataFrame.prepare(df, "department", DOMAIN_MAPPING)

    # Per request -- filter for the current user
    secure = spending.for_user(user)
    secure.df  # only their rows
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import pandas as pd

if TYPE_CHECKING:
    from cognito_auth.user import User

logger = logging.getLogger(__name__)


class AuthorisedDataFrame:
    """DataFrame wrapper that only contains rows a user is authorised to see.

    Resolves a user's email domain to departments via a mapping dict,
    then filters the data so only authorised rows are accessible.

    Args:
        segments: Pre-segmented data as ``{department_name: DataFrame}``.
            Create with ``dict(tuple(df.groupby(auth_column)))``.
        user: Authenticated User object from cognito_auth.
        domain_mapping: Maps email domains to lists of department names,
            e.g. ``{"cabinetoffice.gov.uk": ["Cabinet Office"]}``.

    Attributes:
        user: The authenticated user this frame is filtered for.
        departments: The departments this user can access, or None.
        has_access: Whether the user has any department mapping.
        df: The filtered DataFrame. Only contains authorised rows.
    """

    def __init__(
        self,
        segments: dict[str, pd.DataFrame],
        user: User,
        domain_mapping: dict[str, list[str]],
    ) -> None:
        self.user = user
        self.departments = self._resolve(user, domain_mapping)
        self.has_access = self.departments is not None

        if not self.has_access or not self.departments:
            # Get columns from the first segment if available, else empty
            sample = next(iter(segments.values()), pd.DataFrame())
            self.df = pd.DataFrame(columns=sample.columns)
            return

        matching = [segments[d] for d in self.departments if d in segments]
        if not matching:
            sample = next(iter(segments.values()), pd.DataFrame())
            self.df = pd.DataFrame(columns=sample.columns)
        elif len(matching) == 1:
            self.df = matching[0]
        else:
            self.df = pd.concat(matching, ignore_index=True)

    @staticmethod
    def _resolve(user: User, mapping: dict[str, list[str]]) -> list[str] | None:
        """Resolve a user to their authorised departments.

        Admin users (``user.is_admin``) get access to all departments
        in the mapping. Standard users are looked up by email domain.

        Args:
            user: Authenticated User from cognito_auth.
            mapping: Domain-to-departments mapping dict.

        Returns:
            Sorted list of department names, or None if unmapped.
        """
        if user.is_admin:
            return sorted({d for depts in mapping.values() for d in depts})
        return mapping.get(user.email_domain)

    def to_store(self) -> dict[str, Any]:
        """Serialise for Dash ``dcc.Store`` -- filtered data + user context.

        Returns a dict suitable for writing directly to a ``dcc.Store``
        component. Downstream render callbacks can read from the store
        without needing access to auth or the raw data.

        Returns:
            Dict with keys:
                - ``records``: list of row dicts (empty if no access)
                - ``user_name``: user's display name
                - ``user_email``: user's email address
                - ``departments``: list of authorised department names
                - ``has_access``: whether the user has a department mapping
        """
        return {
            "records": self.df.to_dict("records") if self.has_access else [],
            "user_name": self.user.name,
            "user_email": self.user.email,
            "departments": self.departments,
            "has_access": self.has_access,
        }

    @classmethod
    def prepare(
        cls,
        df: pd.DataFrame,
        auth_column: str,
        domain_mapping: dict[str, list[str]],
    ) -> PreparedDataFrame:
        """Pre-segment a DataFrame for repeated per-user filtering.

        Call this once at app startup to segment the data by
        ``auth_column``. Then call ``.for_user(user)`` on the result
        for each request to get a filtered :class:`AuthorisedDataFrame`.

        Example::

            # Startup
            spending = AuthorisedDataFrame.prepare(df, "department", MAPPING)

            # Per request
            secure = spending.for_user(user)
            secure.df  # filtered

        Args:
            df: The full unfiltered DataFrame.
            auth_column: Column name to segment on (e.g. ``"department"``).
            domain_mapping: Domain-to-departments mapping dict.

        Returns:
            A :class:`PreparedDataFrame` ready for ``.for_user()`` calls.
        """
        segments = dict(tuple(df.groupby(auth_column)))
        return PreparedDataFrame(segments, domain_mapping)


class PreparedDataFrame:
    """Pre-segmented data ready to be filtered per user.

    Created by :meth:`AuthorisedDataFrame.prepare`. Call
    :meth:`for_user` to get a filtered :class:`AuthorisedDataFrame`
    for a specific user.

    Args:
        segments: Pre-segmented data as ``{department_name: DataFrame}``.
        domain_mapping: Domain-to-departments mapping dict.
    """

    def __init__(
        self,
        segments: dict[str, pd.DataFrame],
        domain_mapping: dict[str, list[str]],
    ) -> None:
        self._segments = segments
        self._domain_mapping = domain_mapping

    def for_user(self, user: User) -> AuthorisedDataFrame:
        """Create a filtered DataFrame for a specific user.

        Args:
            user: Authenticated User from cognito_auth.

        Returns:
            :class:`AuthorisedDataFrame` containing only rows the
            user is authorised to see.
        """
        return AuthorisedDataFrame(self._segments, user, self._domain_mapping)

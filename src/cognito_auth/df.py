"""
AuthorisedDataFrame: Row-level security for pandas DataFrames.

Provides a DataFrame wrapper that enforces department-based filtering
based on a User's identity. Requires the [df] extra:

    pip install cognito-auth[df]

Usage:
    from cognito_auth.df import AuthorisedDataFrame
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

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

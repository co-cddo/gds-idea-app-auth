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

logger = logging.getLogger(__name__)

"""
Base authentication class with shared logic for all frameworks.
"""

import os
import warnings

from .authoriser import Authoriser
from .user import User


class BaseAuth:
    """
    Base class with shared authentication logic.

    Not intended to be used directly - use framework-specific classes instead:
    - StreamlitAuth
    - DashAuth
    - FastAPIAuth
    - GradioAuth
    """

    def __init__(
        self,
        authoriser: Authoriser | None = None,
        redirect_url: str = "https://gds-idea.click/401.html",
        region: str = "eu-west-2",
    ):
        """
        Initialize auth. Auto-loads from environment variables if no
        authoriser provided.

        Environment variables:
        - COGNITO_AUTH_CONFIG_PATH: Local JSON file (development)
        - COGNITO_AUTH_SECRET_NAME: AWS Secrets Manager (production)
        - COGNITO_AUTH_DEV_MODE: Use mock users (local development)

        Args:
            authoriser: Pre-configured Authoriser. If None, loads from env vars.
            redirect_url: Where to redirect on auth failure
            region: AWS region
        """
        self.redirect_url = redirect_url
        self.region = region

        # Check for dev mode from environment variable
        self.dev_mode = os.getenv("COGNITO_AUTH_DEV_MODE", "").lower() in (
            "true",
            "1",
            "yes",
        )

        if self.dev_mode:
            warnings.warn(
                "COGNITO_AUTH_DEV_MODE is enabled. Authentication is bypassed and mock "
                "users will be used. This should NEVER be enabled in production.",
                UserWarning,
                stacklevel=3,
            )

        # Auto-load from config if not provided
        if authoriser is None:
            authoriser = Authoriser.from_config()

        self.authoriser = authoriser

    def _get_header(self, headers: dict, name: str) -> str | None:
        """
        Get header value, trying both original case and lowercase.

        AWS ALB sends capitalized headers, but different frameworks may normalize them.

        Args:
            headers: Request headers dictionary
            name: Header name to look for

        Returns:
            Header value or None if not found
        """
        # Try original case first
        value = headers.get(name)
        if value:
            return value
        # Try lowercase
        return headers.get(name.lower())

    def _get_user_from_headers(self, headers: dict) -> User:
        """Extract and validate user from Cognito headers."""
        oidc_header = self._get_header(headers, "X-Amzn-Oidc-Data")
        access_header = self._get_header(headers, "X-Amzn-Oidc-Accesstoken")

        # In dev mode, if headers are missing, return a mock user
        if self.dev_mode and (not oidc_header or not access_header):
            return User.create_mock(region=self.region)

        return User(
            oidc_data_header=oidc_header,
            access_token_header=access_header,
            region=self.region,
            verify_tokens=True,
        )

    def _is_authorised(self, user: User) -> bool:
        """Check if user passes authorisation rules."""
        if self.authoriser is not None and not self.authoriser.is_authorised(user):
            return False
        return True

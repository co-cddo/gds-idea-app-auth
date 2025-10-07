import json
import os
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any

from jose import jwt

from .exceptions import MissingTokenError
from .token_verifier import TokenVerifier


class User:
    """
    Represents an authenticated user from AWS ALB + Cognito.
    """

    def __init__(
        self,
        oidc_data_header: str | None,
        access_token_header: str | None,
        region: str,
        verify_tokens: bool = True,
    ):
        """
        Initialize User from ALB headers.

        Args:
            oidc_data_header: Value of x-amzn-oidc-data header
            access_token_header: Value of x-amzn-oidc-accesstoken header
            region: AWS region (e.g., 'eu-west-2')
            verify_tokens: Whether to verify token signatures (default: True)

        Raises:
            MissingTokenError: If required headers are missing
            InvalidTokenError: If tokens are invalid
            ExpiredTokenError: If tokens have expired
        """
        if not oidc_data_header:
            raise MissingTokenError("x-amzn-oidc-data header is required")
        if not access_token_header:
            raise MissingTokenError("x-amzn-oidc-accesstoken header is required")

        self._region = region
        self._verifier = TokenVerifier(region) if verify_tokens else None

        # Verify and decode tokens
        if verify_tokens:
            self._oidc_claims = self._verifier.verify_alb_token(oidc_data_header)
            self._access_claims = self._verifier.verify_cognito_token(
                access_token_header
            )
        else:
            # Decode without verification (not recommended for production)
            self._oidc_claims = jwt.get_unverified_claims(oidc_data_header)
            self._access_claims = jwt.get_unverified_claims(access_token_header)

        self._is_authenticated = True

    @property
    def is_authenticated(self) -> bool:
        """Whether the user is authenticated"""
        return self._is_authenticated

    @property
    def sub(self) -> str:
        """User's subject identifier (unique user ID)"""
        return self._oidc_claims.get("sub", "")

    @property
    def username(self) -> str:
        """User's username"""
        return self._oidc_claims.get("username", "")

    @property
    def email(self) -> str:
        """User's email address"""
        return self._oidc_claims.get("email", "")

    @property
    def email_domain(self) -> str:
        if self.email:
            return self.email.split("@")[-1]
        return ""

    @property
    def groups(self) -> list[str]:
        """User's Cognito groups"""
        return self._access_claims.get("cognito:groups", [])

    @property
    def is_admin(self) -> bool:
        """Whether the user is an admin (member of gds-idea group)"""
        return "gds-idea" in self.groups

    @property
    def email_verified(self) -> bool:
        """Whether the user's email has been verified"""
        verified = self._oidc_claims.get("email_verified", "false")
        return verified == "true" or verified is True

    @property
    def exp(self) -> datetime | None:
        """Token expiration time"""
        exp_timestamp = self._oidc_claims.get("exp")
        if exp_timestamp:
            return datetime.fromtimestamp(exp_timestamp)
        return None

    @property
    def issuer(self) -> str:
        """Token issuer (Cognito User Pool)"""
        return self._oidc_claims.get("iss", "")

    @property
    def oidc_claims(self) -> dict[str, Any]:
        """All claims from x-amzn-oidc-data token"""
        return self._oidc_claims.copy()

    @property
    def access_claims(self) -> dict[str, Any]:
        """All claims from x-amzn-oidc-accesstoken token"""
        return self._access_claims.copy()

    def __repr__(self) -> str:
        return (
            f"User(username='{self.username}', email='{self.email}', sub='{self.sub}')"
        )

    def __str__(self) -> str:
        return self.email

    @classmethod
    def create_mock(
        cls,
        email: str | None = None,
        username: str | None = None,
        sub: str | None = None,
        groups: list[str] | None = None,
        email_verified: bool = True,
        region: str = "eu-west-2",
        **extra_claims,
    ) -> "User":
        """
        Create a mock user for development and testing.

        This method creates a User instance without requiring valid JWT tokens.
        It loads defaults from .cognito-auth-dev.json if present, and falls back
        to sensible defaults.

        Args:
            email: User's email address
            username: User's username
            sub: User's subject identifier (unique ID)
            groups: List of Cognito groups
            email_verified: Whether email is verified
            region: AWS region
            **extra_claims: Additional claims to include in tokens

        Returns:
            User instance with mock data

        Example:
            >>> user = User.create_mock(email="dev@company.com", groups=["admin"])
            >>> user = User.create_mock()  # Uses defaults from JSON or hardcoded
        """
        warnings.warn(
            "User.create_mock() is being used. This should only be used for "
            "development and testing, never in production.",
            UserWarning,
            stacklevel=2,
        )

        # Load config from JSON if present
        config = cls._load_dev_config()

        # Merge provided values with config and defaults
        email = email or config.get("email", "dev@example.com")
        # Generate UUID-style sub/username like real Cognito tokens
        default_sub = "mock-" + "12345678-1234-1234-1234-123456789abc"
        sub = sub or config.get("sub", default_sub)
        # In real tokens, username is the same as sub (a UUID)
        username = username or config.get("username", sub)
        groups = groups if groups is not None else config.get("groups", [])

        # Build OIDC claims (from ALB header)
        oidc_claims = {
            "sub": sub,
            "email": email,
            "username": username,
            "email_verified": email_verified,
            "exp": int(time.time()) + 3600,  # Expires in 1 hour
            "iss": f"https://cognito-idp.{region}.amazonaws.com/mock-pool",
            **extra_claims,
        }

        # Build access token claims (from Cognito)
        # Match real token structure more closely
        current_time = int(time.time())
        access_claims = {
            "sub": sub,
            "cognito:groups": groups,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/mock-pool",
            "version": 2,
            "client_id": "mock-client-id",
            "token_use": "access",
            "scope": "openid",
            "auth_time": current_time,
            "exp": current_time + 3600,
            "iat": current_time,
            "username": username,
            **extra_claims,
        }

        # Create instance without going through __init__
        instance = cls.__new__(cls)
        instance._region = region
        instance._verifier = None
        instance._oidc_claims = oidc_claims
        instance._access_claims = access_claims
        instance._is_authenticated = True

        return instance

    @staticmethod
    def _load_dev_config() -> dict[str, Any]:
        """Load development config from JSON file."""
        # Check for custom config path via env var
        config_path = os.getenv("COGNITO_AUTH_DEV_CONFIG")
        if config_path:
            path = Path(config_path)
        else:
            # Default to .cognito-auth-dev.json in current directory
            path = Path.cwd() / ".cognito-auth-dev.json"

        if path.exists():
            try:
                with path.open() as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                warnings.warn(
                    f"Failed to load dev config from {path}: {e}",
                    UserWarning,
                    stacklevel=3,
                )
                return {}
        return {}

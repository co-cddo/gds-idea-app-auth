from datetime import datetime
from typing import Any, Optional

from jose import jwt

from .exceptions import MissingTokenError
from .token_verifier import TokenVerifier


class User:
    """
    Represents an authenticated user from AWS ALB + Cognito.
    """

    def __init__(
        self,
        oidc_data_header: Optional[str],
        access_token_header: Optional[str],
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
    def email_verified(self) -> bool:
        """Whether the user's email has been verified"""
        verified = self._oidc_claims.get("email_verified", "false")
        return verified == "true" or verified is True

    @property
    def exp(self) -> Optional[datetime]:
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
        return f"{self.username} ({self.email})"

import time
from typing import Any

import requests
from cachetools import TTLCache
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from .exceptions import ExpiredTokenError, InvalidTokenError

# Cache size constants
# ALB keys: AWS typically maintains 2-3 active keys for rotation at any time
# Setting to 10 provides headroom for multiple key rotations
_ALB_KEYS_CACHE_SIZE = 10

# Cognito JWKS: Single tenant apps typically use 1 User Pool (1 issuer)
# Setting to 5 provides headroom for testing/development environments
_COGNITO_JWKS_CACHE_SIZE = 5


class TokenVerifier:
    """Handles JWT token verification for both ALB and Cognito tokens"""

    def __init__(self, region: str, cache_ttl: int = 3600):
        """
        Initialize the token verifier.

        Args:
            region: AWS region (e.g., 'eu-west-2')
            cache_ttl: Time to cache public keys in seconds (default: 1 hour)
        """
        self.region = region
        self.cache_ttl = cache_ttl
        # Separate TTL caches for ALB and Cognito keys
        self._alb_keys_cache: TTLCache = TTLCache(
            maxsize=_ALB_KEYS_CACHE_SIZE, ttl=cache_ttl
        )
        self._cognito_jwks_cache: TTLCache = TTLCache(
            maxsize=_COGNITO_JWKS_CACHE_SIZE, ttl=cache_ttl
        )

    def _fetch_alb_public_key(self, key_id: str) -> str:
        """Fetch ALB public key from AWS"""
        url = f"https://public-keys.auth.elb.{self.region}.amazonaws.com/{key_id}"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise InvalidTokenError(f"Failed to fetch ALB public key: {e}") from e

    def _fetch_cognito_jwks(self, issuer: str) -> dict[str, Any]:
        """Fetch Cognito JWKS (JSON Web Key Set)"""
        jwks_url = f"{issuer}/.well-known/jwks.json"

        try:
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise InvalidTokenError(f"Failed to fetch Cognito JWKS: {e}") from e

    def _get_cognito_public_key(self, token: str, issuer: str) -> dict[str, Any]:
        """Get the appropriate public key for a Cognito token"""
        # Check cache (TTL handled automatically by TTLCache)
        if issuer in self._cognito_jwks_cache:
            jwks = self._cognito_jwks_cache[issuer]
        else:
            jwks = self._fetch_cognito_jwks(issuer)
            self._cognito_jwks_cache[issuer] = jwks

        # Get key ID from token header
        try:
            headers = jwt.get_unverified_headers(token)
            key_id = headers["kid"]
        except (JWTError, KeyError) as e:
            raise InvalidTokenError(f"Failed to extract key ID from token: {e}") from e

        # Find matching key in JWKS
        for key in jwks.get("keys", []):
            if key["kid"] == key_id:
                return key

        raise InvalidTokenError(f"Public key not found for key ID: {key_id}") from None

    def verify_cognito_token(self, token: str) -> dict[str, Any]:
        """
        Verify and decode Cognito access token.

        Args:
            token: The JWT token from x-amzn-oidc-accesstoken header

        Returns:
            Decoded token claims

        Raises:
            InvalidTokenError: If token is invalid
            ExpiredTokenError: If token has expired
        """
        try:
            # Decode without verification first to get issuer
            unverified_claims = jwt.get_unverified_claims(token)
            issuer = unverified_claims.get("iss")

            if not issuer:
                raise InvalidTokenError("Token missing 'iss' claim")

            # Get public key
            public_key = self._get_cognito_public_key(token, issuer)

            # Verify and decode token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},  # Access tokens don't have aud claim
            )

            return claims

        except ExpiredSignatureError as e:
            raise ExpiredTokenError("Cognito token has expired") from e
        except JWTError as e:
            raise InvalidTokenError(f"Cognito token verification failed: {e}") from e

    def verify_alb_token(self, token: str) -> dict[str, Any]:
        """
        Verify and decode ALB OIDC data token.

        Args:
            token: The JWT token from x-amzn-oidc-data header

        Returns:
            Decoded token claims

        Raises:
            InvalidTokenError: If token is invalid
            ExpiredTokenError: If token has expired
        """
        try:
            # Get key ID from token header
            headers = jwt.get_unverified_headers(token)
            key_id = headers.get("kid")

            if not key_id:
                raise InvalidTokenError("ALB token missing 'kid' in header")

            # Get or fetch public key (TTL handled automatically by TTLCache)
            if key_id in self._alb_keys_cache:
                public_key_pem = self._alb_keys_cache[key_id]
            else:
                public_key_pem = self._fetch_alb_public_key(key_id)
                self._alb_keys_cache[key_id] = public_key_pem

            # Verify and decode token
            claims = jwt.decode(
                token,
                public_key_pem,
                algorithms=["ES256"],  # ALB uses ES256
                options={"verify_aud": False},
            )

            # Check expiration manually since we disabled some checks
            exp = claims.get("exp")
            if exp and exp < time.time():
                raise ExpiredTokenError("ALB token has expired")

            return claims

        except ExpiredSignatureError as e:
            raise ExpiredTokenError("ALB token has expired") from e
        except JWTError as e:
            raise InvalidTokenError(f"ALB token verification failed: {e}") from e

    def clear_cache(self) -> None:
        """
        Clear all cached public keys.

        Useful for testing or forcing fresh key fetches.
        """
        self._alb_keys_cache.clear()
        self._cognito_jwks_cache.clear()

import logging
import os
import re
import time
from collections.abc import Sequence
from typing import Any

import requests
from cachetools import TTLCache
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from .exceptions import ExpiredTokenError, InvalidTokenError

logger = logging.getLogger(__name__)

# Cache size constants
# ALB keys: AWS typically maintains 2-3 active keys for rotation at any time
# Setting to 10 provides headroom for multiple key rotations
_ALB_KEYS_CACHE_SIZE = 10

# Cognito JWKS: Single tenant apps typically use 1 User Pool (1 issuer)
# Setting to 5 provides headroom for testing/development environments
_COGNITO_JWKS_CACHE_SIZE = 5

# Environment variables that pin which Cognito user pool, app client(s) and
# ALB(s) this process trusts. Comma-separate multiple client IDs / ALB ARNs.
ENV_USER_POOL_ID = "COGNITO_AUTH_USER_POOL_ID"
ENV_CLIENT_IDS = "COGNITO_AUTH_CLIENT_IDS"
ENV_ALB_ARNS = "COGNITO_AUTH_ALB_ARNS"

# https://cognito-idp.<region>.amazonaws.com/<pool id>. Deliberately strict
# about the host: the issuer in an *unverified* token decides which JWKS URL
# we fetch, so it must never be able to point anywhere but Cognito.
_COGNITO_ISSUER_RE = re.compile(
    r"^https://cognito-idp\.(?P<region>[a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com"
    r"/(?P<pool>[A-Za-z0-9_-]+)$"
)

# ALB signing key IDs are interpolated into a URL path, so restrict them to
# characters that cannot alter the path, query or host.
_ALB_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

_warned_unpinned = False


def _split_env(name: str) -> list[str] | None:
    """Read a comma-separated env var; unset or empty means 'not configured'."""
    values = [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]
    return values or None


def _pool_issuer(user_pool_id: str) -> str:
    """Build the issuer URL for a user pool ID like 'eu-west-2_AbCdEf'."""
    region, sep, _ = user_pool_id.partition("_")
    if not sep or not region:
        raise ValueError(
            f"Invalid Cognito user pool ID {user_pool_id!r}; "
            "expected the form '<region>_<id>', e.g. 'eu-west-2_AbCdEfGhI'"
        )
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"


class TokenVerifier:
    """Handles JWT token verification for both ALB and Cognito tokens"""

    def __init__(
        self,
        region: str,
        cache_ttl: int = 3600,
        *,
        user_pool_id: str | None = None,
        client_ids: Sequence[str] | None = None,
        alb_arns: Sequence[str] | None = None,
    ):
        """
        Initialize the token verifier.

        Signature checks alone only prove a token was signed by *some* key
        the token points at. To trust it, we also need to know it came from
        OUR user pool and OUR load balancer. Pin those with the arguments
        below, or the matching environment variables (used when the argument
        is not given):

        Args:
            region: AWS region (e.g., 'eu-west-2')
            cache_ttl: Time to cache public keys in seconds (default: 1 hour)
            user_pool_id: Expected Cognito user pool ID (e.g.
                'eu-west-2_AbCdEfGhI'). The access token's issuer must match
                exactly. Env: COGNITO_AUTH_USER_POOL_ID.
            client_ids: Allowed Cognito app client IDs; the access token's
                `client_id` claim must be one of them.
                Env: COGNITO_AUTH_CLIENT_IDS (comma-separated).
            alb_arns: Allowed ALB ARNs; the `signer` in the ALB token header
                must be one of them. Env: COGNITO_AUTH_ALB_ARNS
                (comma-separated).

        Without a pin the matching check cannot be made. Access tokens must
        still be issued by a Cognito user pool host, but any pool - and any
        AWS load balancer in the region - is accepted, so anyone able to send
        requests to your app directly (bypassing your ALB) could present
        self-signed identities. Configure the pins in production.

        Raises:
            ValueError: If `user_pool_id` is malformed.
        """
        self.region = region
        self.cache_ttl = cache_ttl

        user_pool_id = user_pool_id or os.getenv(ENV_USER_POOL_ID) or None
        client_ids = client_ids or _split_env(ENV_CLIENT_IDS)
        alb_arns = alb_arns or _split_env(ENV_ALB_ARNS)

        self._expected_issuer = _pool_issuer(user_pool_id) if user_pool_id else None
        self._client_ids = frozenset(client_ids) if client_ids else None
        self._alb_arns = frozenset(alb_arns) if alb_arns else None

        global _warned_unpinned
        if not _warned_unpinned and not (self._expected_issuer and self._alb_arns):
            _warned_unpinned = True
            missing = []
            if not self._expected_issuer:
                missing.append(ENV_USER_POOL_ID)
            if not self._alb_arns:
                missing.append(ENV_ALB_ARNS)
            logger.warning(
                "Token verification is not fully pinned (%s not set): tokens "
                "from any Cognito user pool / AWS load balancer will be "
                "accepted. Set these to trust only your own.",
                ", ".join(missing),
            )

        # Separate TTL caches for ALB and Cognito keys
        self._alb_keys_cache: TTLCache = TTLCache(
            maxsize=_ALB_KEYS_CACHE_SIZE, ttl=cache_ttl
        )
        self._cognito_jwks_cache: TTLCache = TTLCache(
            maxsize=_COGNITO_JWKS_CACHE_SIZE, ttl=cache_ttl
        )

    def _check_cognito_issuer(self, issuer: str) -> None:
        """Reject an issuer we must not fetch signing keys from.

        Runs BEFORE any network request: the issuer comes from the
        unverified token, so trusting it would let a caller choose which
        JWKS URL we download and verify against.
        """
        if self._expected_issuer is not None:
            if issuer != self._expected_issuer:
                raise InvalidTokenError("Cognito token issuer is not the expected pool")
            return

        if not _COGNITO_ISSUER_RE.match(issuer):
            raise InvalidTokenError("Cognito token issuer is not a Cognito user pool")

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

            self._check_cognito_issuer(issuer)

            # Get public key
            public_key = self._get_cognito_public_key(token, issuer)

            # Verify and decode token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},  # Access tokens don't have aud claim
            )

            # This token is used for its group membership, so it must be an
            # access token (not e.g. an ID token, which has no cognito:groups
            # guarantees and a different purpose).
            if claims.get("token_use") != "access":
                raise InvalidTokenError("Cognito token is not an access token")

            if self._client_ids is not None and claims.get("client_id") not in (
                self._client_ids
            ):
                raise InvalidTokenError("Cognito token client_id is not allowed")

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
        logger.debug("Starting ALB token verification")
        try:
            # Get key ID from token header
            headers = jwt.get_unverified_headers(token)
            key_id = headers.get("kid")
            logger.debug(f"ALB token key_id: {key_id}")

            if not key_id:
                raise InvalidTokenError("ALB token missing 'kid' in header")
            if not isinstance(key_id, str) or not _ALB_KEY_ID_RE.match(key_id):
                raise InvalidTokenError("ALB token has a malformed 'kid' in header")

            # The signer is part of the signed header. Without checking it,
            # a token minted by anyone's ALB (valid AWS key, wrong account)
            # would verify.
            if self._alb_arns is not None and headers.get("signer") not in (
                self._alb_arns
            ):
                raise InvalidTokenError("ALB token signer is not an allowed ALB")

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
            logger.debug(f"ALB token claims extracted, exp={exp}")
            if exp:
                now = time.time()
                time_until_exp = exp - now
                logger.debug(
                    f"ALB token expiration check: exp={exp}, now={now}, "
                    f"time_until_expiry={time_until_exp:.0f}s"
                )
                if exp < now:
                    logger.warning(
                        f"ALB token EXPIRED: expired {-time_until_exp:.0f}s ago"
                    )
                    raise ExpiredTokenError(
                        f"ALB token has expired (was valid until {exp}, "
                        f"now is {now}, expired {-time_until_exp:.0f}s ago)"
                    )
                else:
                    logger.debug(f"ALB token valid for {time_until_exp:.0f}s more")
            else:
                logger.warning("ALB token has no 'exp' claim!")

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

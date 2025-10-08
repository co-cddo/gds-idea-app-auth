import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from jose import jwt

from cognito_auth.exceptions import ExpiredTokenError, InvalidTokenError
from cognito_auth.token_verifier import TokenVerifier


@pytest.fixture
def verifier():
    """Fixture providing a TokenVerifier instance"""
    return TokenVerifier(region="eu-west-2", cache_ttl=3600)


@pytest.fixture
def mock_alb_public_key():
    """Fixture providing a mock ALB public key"""
    # This is a simplified mock - real keys are much longer
    return "-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----"


@pytest.fixture
def mock_cognito_jwks():
    """Fixture providing mock Cognito JWKS"""
    return {
        "keys": [
            {
                "kid": "test-key-id",
                "kty": "RSA",
                "n": "mock_n",
                "e": "AQAB",
            }
        ]
    }


# Tests for cache functionality


def test_alb_cache_stores_key(verifier, mock_alb_public_key):
    """ALB keys are cached after first fetch"""
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.text = mock_alb_public_key
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # First call fetches
        key1 = verifier._fetch_alb_public_key("key-123")
        assert key1 == mock_alb_public_key
        assert mock_get.call_count == 1

        # Manually add to cache to test caching behavior
        verifier._alb_keys_cache["key-123"] = mock_alb_public_key

        # Check cache works
        assert "key-123" in verifier._alb_keys_cache
        assert verifier._alb_keys_cache["key-123"] == mock_alb_public_key


def test_cognito_cache_stores_jwks(verifier, mock_cognito_jwks):
    """Cognito JWKS are cached after first fetch"""
    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = mock_cognito_jwks
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # First call fetches
        jwks1 = verifier._fetch_cognito_jwks(issuer)
        assert jwks1 == mock_cognito_jwks
        assert mock_get.call_count == 1

        # Manually add to cache
        verifier._cognito_jwks_cache[issuer] = mock_cognito_jwks

        # Check cache works
        assert issuer in verifier._cognito_jwks_cache
        assert verifier._cognito_jwks_cache[issuer] == mock_cognito_jwks


def test_clear_cache_clears_both_caches(verifier):
    """clear_cache removes all cached keys"""
    # Add items to both caches
    verifier._alb_keys_cache["key-1"] = "mock-key-1"
    verifier._cognito_jwks_cache["issuer-1"] = {"keys": []}

    assert len(verifier._alb_keys_cache) == 1
    assert len(verifier._cognito_jwks_cache) == 1

    # Clear cache
    verifier.clear_cache()

    assert len(verifier._alb_keys_cache) == 0
    assert len(verifier._cognito_jwks_cache) == 0


def test_cache_ttl_expiration():
    """Cache entries expire after TTL"""
    # Create verifier with very short TTL
    verifier = TokenVerifier(region="eu-west-2", cache_ttl=1)

    # Add entry to cache
    verifier._alb_keys_cache["key-1"] = "mock-key"
    assert "key-1" in verifier._alb_keys_cache

    # Wait for TTL to expire
    time.sleep(1.1)

    # Entry should be gone
    assert "key-1" not in verifier._alb_keys_cache


# Tests for error handling


def test_fetch_alb_public_key_network_error(verifier):
    """_fetch_alb_public_key raises InvalidTokenError on network failure"""
    with patch("cognito_auth.token_verifier.requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(InvalidTokenError, match="Failed to fetch ALB public key"):
            verifier._fetch_alb_public_key("key-123")


def test_fetch_cognito_jwks_network_error(verifier):
    """_fetch_cognito_jwks raises InvalidTokenError on network failure"""
    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"

    with patch("cognito_auth.token_verifier.requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(InvalidTokenError, match="Failed to fetch Cognito JWKS"):
            verifier._fetch_cognito_jwks(issuer)


def test_get_cognito_public_key_missing_kid():
    """_get_cognito_public_key raises error when token missing kid"""
    verifier = TokenVerifier(region="eu-west-2")

    # Create token without kid in header
    token = jwt.encode({"sub": "test"}, "secret", algorithm="HS256")

    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"
    verifier._cognito_jwks_cache[issuer] = {"keys": []}

    with pytest.raises(InvalidTokenError, match="Failed to extract key ID"):
        verifier._get_cognito_public_key(token, issuer)


def test_get_cognito_public_key_key_not_found(verifier, mock_cognito_jwks):
    """_get_cognito_public_key raises error when key not in JWKS"""
    # Create a token with kid that doesn't match
    token = jwt.encode(
        {"sub": "test"}, "secret", algorithm="HS256", headers={"kid": "wrong-key-id"}
    )

    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"
    verifier._cognito_jwks_cache[issuer] = mock_cognito_jwks

    with pytest.raises(InvalidTokenError, match="Public key not found"):
        verifier._get_cognito_public_key(token, issuer)


def test_verify_cognito_token_missing_issuer(verifier):
    """verify_cognito_token raises error when token missing issuer"""
    # Create token without iss claim
    token = jwt.encode({"sub": "test"}, "secret", algorithm="HS256")

    with pytest.raises(InvalidTokenError, match="Token missing 'iss' claim"):
        verifier.verify_cognito_token(token)


def test_verify_alb_token_missing_kid(verifier):
    """verify_alb_token raises error when token missing kid"""
    # Create token without kid in header
    token = jwt.encode({"sub": "test"}, "secret", algorithm="HS256")

    with pytest.raises(InvalidTokenError, match="ALB token missing 'kid'"):
        verifier.verify_alb_token(token)


# Tests for cache behavior with get methods


def test_get_cognito_public_key_uses_cache(verifier, mock_cognito_jwks):
    """_get_cognito_public_key uses cached JWKS"""
    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"

    # Pre-populate cache
    verifier._cognito_jwks_cache[issuer] = mock_cognito_jwks

    # Create token with matching kid
    token = jwt.encode(
        {"sub": "test"},
        "secret",
        algorithm="HS256",
        headers={"kid": "test-key-id"},
    )

    with patch.object(verifier, "_fetch_cognito_jwks") as mock_fetch:
        # Should use cache, not fetch
        key = verifier._get_cognito_public_key(token, issuer)
        assert key["kid"] == "test-key-id"
        mock_fetch.assert_not_called()


def test_get_cognito_public_key_fetches_when_not_cached(verifier, mock_cognito_jwks):
    """_get_cognito_public_key fetches JWKS when not cached"""
    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"

    # Create token with matching kid
    token = jwt.encode(
        {"sub": "test"},
        "secret",
        algorithm="HS256",
        headers={"kid": "test-key-id"},
    )

    with patch.object(
        verifier, "_fetch_cognito_jwks", return_value=mock_cognito_jwks
    ) as mock_fetch:
        key = verifier._get_cognito_public_key(token, issuer)
        assert key["kid"] == "test-key-id"
        mock_fetch.assert_called_once_with(issuer)


# Tests for successful verification (mocked)


def test_verify_cognito_token_success(verifier, mock_cognito_jwks):
    """verify_cognito_token successfully verifies valid token"""
    issuer = "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"
    expected_claims = {
        "sub": "user-123",
        "iss": issuer,
        "username": "testuser",
        "cognito:groups": ["users"],
    }

    # Mock the decode to return our claims
    with (
        patch("cognito_auth.token_verifier.jwt.decode") as mock_decode,
        patch("cognito_auth.token_verifier.jwt.get_unverified_claims") as mock_claims,
        patch("cognito_auth.token_verifier.jwt.get_unverified_headers") as mock_headers,
    ):
        mock_claims.return_value = {"iss": issuer}
        mock_headers.return_value = {"kid": "test-key-id"}
        mock_decode.return_value = expected_claims

        # Pre-populate cache to avoid fetch
        verifier._cognito_jwks_cache[issuer] = mock_cognito_jwks

        token = "mock.jwt.token"
        claims = verifier.verify_cognito_token(token)

        assert claims == expected_claims
        mock_decode.assert_called_once()


def test_verify_alb_token_success(verifier, mock_alb_public_key):
    """verify_alb_token successfully verifies valid token"""
    expected_claims = {
        "sub": "user-123",
        "email": "test@example.com",
        "exp": int(time.time()) + 3600,
    }

    with (
        patch("cognito_auth.token_verifier.jwt.decode") as mock_decode,
        patch("cognito_auth.token_verifier.jwt.get_unverified_headers") as mock_headers,
    ):
        mock_headers.return_value = {"kid": "key-123"}
        mock_decode.return_value = expected_claims

        # Pre-populate cache
        verifier._alb_keys_cache["key-123"] = mock_alb_public_key

        token = "mock.jwt.token"
        claims = verifier.verify_alb_token(token)

        assert claims == expected_claims
        mock_decode.assert_called_once()


# Tests for expired tokens


def test_verify_alb_token_expired_in_claims(verifier, mock_alb_public_key):
    """verify_alb_token raises ExpiredTokenError for expired token (exp in claims)"""
    expired_claims = {
        "sub": "user-123",
        "email": "test@example.com",
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
    }

    with (
        patch("cognito_auth.token_verifier.jwt.decode") as mock_decode,
        patch("cognito_auth.token_verifier.jwt.get_unverified_headers") as mock_headers,
    ):
        mock_headers.return_value = {"kid": "key-123"}
        mock_decode.return_value = expired_claims

        verifier._alb_keys_cache["key-123"] = mock_alb_public_key

        token = "mock.jwt.token"
        with pytest.raises(ExpiredTokenError, match="ALB token has expired"):
            verifier.verify_alb_token(token)

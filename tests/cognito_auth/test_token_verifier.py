import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from jose import jwk, jwt

from cognito_auth import token_verifier
from cognito_auth.exceptions import ExpiredTokenError, InvalidTokenError
from cognito_auth.token_verifier import TokenVerifier


@pytest.fixture(autouse=True)
def _clean_pin_config(monkeypatch):
    """Pinning is driven by env vars - make sure the host's never leak in."""
    for name in (
        token_verifier.ENV_USER_POOL_ID,
        token_verifier.ENV_CLIENT_IDS,
        token_verifier.ENV_ALB_ARNS,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(token_verifier, "_warned_unpinned", False)


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
        "token_use": "access",
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


# Tests for issuer / client / signer pinning
#
# These use real RSA / EC signatures (not mocked jwt.decode) so they prove the
# verifier rejects tokens that are validly signed - just not by anyone we
# trust. That is exactly the forgery a caller bypassing the ALB could attempt.

POOL_ID = "eu-west-2_TestPool1"
POOL_ISSUER = f"https://cognito-idp.eu-west-2.amazonaws.com/{POOL_ID}"
ALB_ARN = "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/x/1"


def _rsa_key():
    """Generate a throwaway RSA key using python-jose's own pure-Python backend."""
    import rsa

    public, private = rsa.newkeys(2048)
    jwk_dict = jwk.construct(public.save_pkcs1(), "RS256").to_dict()
    jwk_dict.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    return private.save_pkcs1().decode(), {"keys": [jwk_dict]}


def _access_token(pem, **overrides):
    claims = {
        "iss": POOL_ISSUER,
        "token_use": "access",
        "client_id": "client-a",
        "cognito:groups": ["gds-idea"],
        "exp": int(time.time()) + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "k1"})


def test_forged_issuer_is_rejected_before_any_network_request():
    """A self-signed token must not make us download its chosen JWKS."""
    pem, _ = _rsa_key()
    token = _access_token(pem, iss="https://attacker.example.com/pool")

    with patch("requests.get") as mock_get:
        with pytest.raises(InvalidTokenError, match="not a Cognito user pool"):
            TokenVerifier("eu-west-2").verify_cognito_token(token)

    mock_get.assert_not_called()


@pytest.mark.parametrize(
    "issuer",
    [
        "http://cognito-idp.eu-west-2.amazonaws.com/pool",
        "https://cognito-idp.eu-west-2.amazonaws.com.evil.com/pool",
        "https://evil.com/cognito-idp.eu-west-2.amazonaws.com/pool",
        "https://cognito-idp.eu-west-2.amazonaws.com@evil.com/pool",
        "https://cognito-idp.eu-west-2.amazonaws.com/pool/extra",
        "https://cognito-idp.eu-west-2.amazonaws.com/pool?x=1",
        "https://cognito-idp.eu-west-2.amazonaws.com/",
        "file:///etc/passwd",
    ],
)
def test_malformed_or_lookalike_issuers_are_rejected(issuer):
    with pytest.raises(InvalidTokenError):
        TokenVerifier("eu-west-2")._check_cognito_issuer(issuer)


def test_any_cognito_pool_is_accepted_when_unpinned(verifier):
    verifier._check_cognito_issuer(POOL_ISSUER)
    verifier._check_cognito_issuer(
        "https://cognito-idp.eu-west-2.amazonaws.com/test-pool"
    )


def test_pinned_pool_rejects_other_cognito_pools():
    verifier = TokenVerifier("eu-west-2", user_pool_id=POOL_ID)
    with pytest.raises(InvalidTokenError, match="expected pool"):
        verifier._check_cognito_issuer(
            "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_OtherPool"
        )
    verifier._check_cognito_issuer(POOL_ISSUER)


def test_pinned_pool_via_env(monkeypatch):
    monkeypatch.setenv(token_verifier.ENV_USER_POOL_ID, POOL_ID)
    with pytest.raises(InvalidTokenError):
        TokenVerifier("eu-west-2")._check_cognito_issuer(
            "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_OtherPool"
        )


def test_malformed_user_pool_id_fails_fast():
    with pytest.raises(ValueError, match="user pool ID"):
        TokenVerifier("eu-west-2", user_pool_id="not-a-pool-id")


def test_valid_signed_access_token_is_accepted_when_fully_pinned():
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2", user_pool_id=POOL_ID, client_ids=["client-a"])
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks

    claims = verifier.verify_cognito_token(_access_token(pem))

    assert claims["cognito:groups"] == ["gds-idea"]


def test_id_tokens_are_rejected():
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2", user_pool_id=POOL_ID)
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks

    with pytest.raises(InvalidTokenError, match="not an access token"):
        verifier.verify_cognito_token(_access_token(pem, token_use="id"))


def test_token_without_token_use_is_rejected():
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2", user_pool_id=POOL_ID)
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks
    token = jwt.encode(
        {"iss": POOL_ISSUER, "exp": int(time.time()) + 60},
        pem,
        algorithm="RS256",
        headers={"kid": "k1"},
    )

    with pytest.raises(InvalidTokenError, match="not an access token"):
        verifier.verify_cognito_token(token)


def test_unlisted_client_id_is_rejected():
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2", user_pool_id=POOL_ID, client_ids=["client-a"])
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks

    with pytest.raises(InvalidTokenError, match="client_id"):
        verifier.verify_cognito_token(_access_token(pem, client_id="client-b"))

    # Missing claim is also rejected, not skipped.
    with pytest.raises(InvalidTokenError, match="client_id"):
        verifier.verify_cognito_token(_access_token(pem, client_id=None))


def test_client_ids_via_env_are_comma_separated(monkeypatch):
    monkeypatch.setenv(token_verifier.ENV_CLIENT_IDS, "client-a, client-b ,")
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2")
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks

    assert verifier.verify_cognito_token(_access_token(pem, client_id="client-b"))
    with pytest.raises(InvalidTokenError):
        verifier.verify_cognito_token(_access_token(pem, client_id="client-c"))


def test_client_id_not_checked_when_unpinned():
    pem, jwks = _rsa_key()
    verifier = TokenVerifier("eu-west-2")
    verifier._cognito_jwks_cache[POOL_ISSUER] = jwks

    assert verifier.verify_cognito_token(_access_token(pem, client_id="anything"))


@pytest.mark.parametrize(
    "kid",
    [
        "../../etc/passwd",
        "abc/def",
        "abc?x=1",
        "abc#frag",
        "a" * 200,
        "abc def",
        "evil.com/x",
    ],
)
def test_alb_kid_that_could_alter_the_key_url_is_rejected(kid):
    token = jwt.encode({"sub": "x"}, "secret", algorithm="HS256", headers={"kid": kid})

    with patch("requests.get") as mock_get:
        with pytest.raises(InvalidTokenError, match="malformed 'kid'"):
            TokenVerifier("eu-west-2").verify_alb_token(token)

    mock_get.assert_not_called()


def test_alb_token_from_unlisted_signer_is_rejected():
    """A token signed by someone else's ALB has a valid AWS key but wrong signer."""
    token = jwt.encode(
        {"sub": "x"},
        "secret",
        algorithm="HS256",
        headers={"kid": "abc-123", "signer": "arn:aws:elasticloadbalancing:other"},
    )
    verifier = TokenVerifier("eu-west-2", alb_arns=[ALB_ARN])

    with patch("requests.get") as mock_get:
        with pytest.raises(InvalidTokenError, match="signer"):
            verifier.verify_alb_token(token)

    mock_get.assert_not_called()


def test_alb_token_without_signer_is_rejected_when_pinned():
    token = jwt.encode(
        {"sub": "x"}, "secret", algorithm="HS256", headers={"kid": "abc-123"}
    )

    with pytest.raises(InvalidTokenError, match="signer"):
        TokenVerifier("eu-west-2", alb_arns=[ALB_ARN]).verify_alb_token(token)


def test_alb_token_from_allowed_signer_is_accepted(mock_alb_public_key):
    verifier = TokenVerifier("eu-west-2", alb_arns=[ALB_ARN])
    claims = {"sub": "u", "exp": int(time.time()) + 60}

    with (
        patch("cognito_auth.token_verifier.jwt.get_unverified_headers") as headers,
        patch("cognito_auth.token_verifier.jwt.decode", return_value=claims),
    ):
        headers.return_value = {"kid": "abc-123", "signer": ALB_ARN}
        verifier._alb_keys_cache["abc-123"] = mock_alb_public_key

        assert verifier.verify_alb_token("mock.jwt.token") == claims


def test_alb_signer_via_env(monkeypatch):
    monkeypatch.setenv(token_verifier.ENV_ALB_ARNS, f"{ALB_ARN},arn:other")
    token = jwt.encode(
        {"sub": "x"},
        "secret",
        algorithm="HS256",
        headers={"kid": "abc-123", "signer": "arn:not-listed"},
    )

    with pytest.raises(InvalidTokenError, match="signer"):
        TokenVerifier("eu-west-2").verify_alb_token(token)


def test_warns_once_when_not_pinned(caplog):
    with caplog.at_level("WARNING", logger="cognito_auth.token_verifier"):
        TokenVerifier("eu-west-2")
        TokenVerifier("eu-west-2")

    warnings_logged = [r for r in caplog.records if "not fully pinned" in r.message]
    assert len(warnings_logged) == 1
    assert token_verifier.ENV_USER_POOL_ID in warnings_logged[0].getMessage()


def test_no_warning_when_fully_pinned(caplog):
    with caplog.at_level("WARNING", logger="cognito_auth.token_verifier"):
        TokenVerifier("eu-west-2", user_pool_id=POOL_ID, alb_arns=[ALB_ARN])

    assert not [r for r in caplog.records if "not fully pinned" in r.message]

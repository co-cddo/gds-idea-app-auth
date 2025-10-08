# Exceptions

Custom exceptions raised by cognito-auth.

## InvalidTokenError

::: cognito_auth.exceptions.InvalidTokenError
    options:
      show_root_heading: true

Raised when a JWT token fails signature verification or is malformed.

**Common causes:**
- Token signature doesn't match public key
- Token is malformed or corrupted
- Token was not issued by the expected ALB or Cognito User Pool

**Example:**
```python
from cognito_auth import User
from cognito_auth.exceptions import InvalidTokenError

try:
    user = User(
        oidc_data_header="invalid-token",
        access_token_header="invalid-token",
        region="eu-west-2",
        verify_tokens=True
    )
except InvalidTokenError as e:
    print(f"Token validation failed: {e}")
```

## ExpiredTokenError

::: cognito_auth.exceptions.ExpiredTokenError
    options:
      show_root_heading: true

Raised when a JWT token has expired.

**Common causes:**
- User's session has timed out
- Token expiration time (`exp` claim) is in the past
- System clock skew

**Example:**
```python
from cognito_auth import User
from cognito_auth.exceptions import ExpiredTokenError

try:
    user = User(
        oidc_data_header=expired_token,
        access_token_header=access_token,
        region="eu-west-2",
        verify_tokens=True
    )
except ExpiredTokenError as e:
    print(f"Token expired: {e}")
    # Redirect user to re-authenticate
```

## MissingTokenError

::: cognito_auth.exceptions.MissingTokenError
    options:
      show_root_heading: true

Raised when required Cognito headers are missing from the request.

**Common causes:**
- Application not behind ALB with OIDC authentication enabled
- Headers not properly forwarded by load balancer
- Testing without dev mode enabled

**Example:**
```python
from cognito_auth import User
from cognito_auth.exceptions import MissingTokenError

try:
    user = User(
        oidc_data_header=None,  # Missing header
        access_token_header="token",
        region="eu-west-2",
        verify_tokens=True
    )
except MissingTokenError as e:
    print(f"Required headers missing: {e}")
```

## Handling Exceptions

Framework auth classes handle these exceptions automatically:

**StreamlitAuth:**
```python
# Automatically catches exceptions and calls st.stop()
user = auth.get_auth_user()
```

**DashAuth / FastAPIAuth / GradioAuth:**
```python
# Automatically redirects or raises HTTPException
user = auth.get_auth_user()
```

**Manual handling:**
```python
from cognito_auth import User
from cognito_auth.exceptions import (
    InvalidTokenError,
    ExpiredTokenError,
    MissingTokenError
)

try:
    user = User(
        oidc_data_header=oidc_token,
        access_token_header=access_token,
        region="eu-west-2",
        verify_tokens=True
    )
except MissingTokenError:
    # Redirect to login
    pass
except ExpiredTokenError:
    # Session expired, re-authenticate
    pass
except InvalidTokenError:
    # Tampered or invalid token
    pass
```

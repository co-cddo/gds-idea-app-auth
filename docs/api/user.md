# User

The `User` class represents an authenticated user from AWS Cognito via ALB OIDC headers.

::: cognito_auth.user.User
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - create_mock
        - sub
        - username
        - email
        - email_domain
        - groups
        - is_authenticated
        - is_admin
        - email_verified
        - exp
        - issuer
        - oidc_claims
        - access_claims

## Examples

### Creating a User from Headers

In production, the User is automatically created by framework auth classes:

```python
from cognito_auth.streamlit import StreamlitAuth

auth = StreamlitAuth()
user = auth.get_auth_user()  # User created from request headers

print(f"Email: {user.email}")
print(f"Groups: {user.groups}")
print(f"Is Admin: {user.is_admin}")
```

### Creating a Mock User for Testing

For local development and testing:

```python
from cognito_auth import User

# With defaults
user = User.create_mock()

# With custom values
user = User.create_mock(
    email="developer@example.com",
    groups=["developers", "admin"]
)

assert user.is_authenticated is True
assert "developers" in user.groups
```

## Properties

All user properties are read-only and extracted from the JWT tokens.

### Authentication Properties

- **`is_authenticated`**: Whether the user is authenticated (tokens are valid)
- **`email_verified`**: Whether the user's email is verified in Cognito

### Identity Properties

- **`sub`**: User's unique subject identifier (UUID)
- **`username`**: User's username (typically same as `sub`)
- **`email`**: User's email address
- **`email_domain`**: Domain portion of email (e.g., "example.com")

### Authorisation Properties

- **`groups`**: List of Cognito groups the user belongs to
- **`is_admin`**: Whether user belongs to "gds-idea" admin group

### Token Properties

- **`exp`**: Token expiration timestamp
- **`issuer`**: Token issuer URL
- **`oidc_claims`**: All claims from ALB OIDC token
- **`access_claims`**: All claims from Cognito access token

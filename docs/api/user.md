# User

The `User` class represents an authenticated user from AWS Cognito via ALB OIDC headers. It's the core object you'll interact with after authentication and contains all relevant user information.

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

## Usage

The `User` object is typically obtained from your framework's Auth class:

```python
# Streamlit example
from cognito_auth.streamlit import StreamlitAuth

auth = StreamlitAuth()
user = auth.get_auth_user()

# FastAPI example
from fastapi import FastAPI, Depends
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()

@app.get("/")
def index(user = Depends(auth.get_auth_user)):
    return {"email": user.email}
```

## Properties

All user properties are read-only and extracted from the JWT tokens:

| Property | Type | Description |
|----------|------|-------------|
| `email` | str | User's email address |
| `email_domain` | str | Domain portion of email (e.g., "example.com") |
| `groups` | list[str] | List of Cognito groups the user belongs to |
| `is_authenticated` | bool | Whether the user is authenticated (tokens valid) |
| `is_admin` | bool | Whether user belongs to admin group (configurable) |
| `email_verified` | bool | Whether email is verified in Cognito |
| `sub` | str | User's unique subject identifier (UUID) |
| `username` | str | User's username (typically same as `sub`) |
| `exp` | int | Token expiration timestamp |
| `issuer` | str | Token issuer URL |
| `oidc_claims` | dict | All claims from ALB OIDC token |
| `access_claims` | dict | All claims from Cognito access token |

## Examples

### Accessing User Information

```python
# Get user's email
email = user.email  # "user@example.com"

# Check if user is in a group
if "admin" in user.groups:
    # Admin-only actions
    pass

# Check email domain
if user.email_domain == "digital.cabinet-office.gov.uk":
    # Government email domain
    pass

# Check if user is an admin
if user.is_admin:
    # Show admin features
    pass
```

### Creating a Mock User for Testing

For local development and testing without AWS ALB, you can create mock users:

```python
from cognito_auth import User

# With default values
user = User.create_mock()
# Default: email="user@example.com", groups=["developers"]

# With custom values
user = User.create_mock(
    email="developer@example.com",
    groups=["developers", "admin"],
    email_verified=True
)

assert user.is_authenticated is True
assert "developers" in user.groups
assert user.email == "developer@example.com"
```

### Mock User from Configuration File

When using development mode, you can specify a mock user in a JSON file:

```json
{
  "email": "tester@digital.cabinet-office.gov.uk",
  "groups": ["developers", "admin", "tester"],
  "email_verified": true
}
```

Then set the environment variable:

```bash
export COGNITO_AUTH_MOCK_USER_PATH=./dev-mock-user.json
export COGNITO_AUTH_DEV_MODE=true
```

## Security Considerations

The `User` object's properties are read-only to prevent tampering with authentication information. All user information is derived from verified JWT tokens.

The token verification process:

1. Extracts JWT tokens from request headers
2. Verifies token signatures against public keys
3. Validates token expiration and issuer
4. Creates the User object only if verification succeeds

## Common Use Cases

### Role-Based Access Control

```python
def check_access(user, required_groups):
    """Check if user has access to a feature"""
    return any(group in user.groups for group in required_groups)

# Usage
if check_access(user, ["admin", "editor"]):
    # Allow access
    pass
```

### Multi-Tenant Applications

```python
def get_tenant_data(user):
    """Get data for user's tenant based on email domain"""
    tenant = user.email_domain
    # Fetch data for this tenant
    return tenant_data[tenant]
```

### User Profile Information

```python
def get_user_profile(user):
    """Create a user profile from auth info"""
    return {
        "email": user.email,
        "roles": user.groups,
        "verified": user.email_verified,
        "id": user.sub
    }
```

## Related Classes

- `TokenVerifier`: Handles the verification of JWT tokens
- `Authoriser`: Manages authorization rules and checks
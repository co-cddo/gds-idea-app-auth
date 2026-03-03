# Development Mode

For local development without AWS ALB, cognito-auth provides a dev mode that returns mock users instead of requiring real OIDC headers.

!!! warning
    Never enable dev mode in production. Authentication is completely bypassed.

## Enabling Dev Mode

Set the environment variable:

```bash
export COGNITO_AUTH_DEV_MODE=true
```

When dev mode is enabled and OIDC headers are missing, `get_auth_user()` returns a mock user instead of raising an error. Your auth code works identically in development and production -- no code changes needed.

## Customising the Mock User

By default, the mock user has:

- **email**: `dev@example.com`
- **name**: `Dev User`
- **given_name**: `Dev`
- **family_name**: `User`
- **groups**: `[]` (empty)

To customise, create a `dev-mock-user.json` file in your project root:

```json
{
  "email": "developer@example.com",
  "sub": "12345678-1234-1234-1234-123456789abc",
  "username": "12345678-1234-1234-1234-123456789abc",
  "name": "Dev User",
  "given_name": "Dev",
  "family_name": "User",
  "groups": ["developers", "users"]
}
```

The mock user will use these values instead of the defaults. This is useful for testing different authorisation scenarios locally.

**Available fields:**

| Field | Description |
|---|---|
| `email` | Mock user's email address |
| `sub` | Mock user's Cognito subject (UUID) |
| `username` | Mock user's username (usually same as `sub`) |
| `name` | Mock user's full display name |
| `given_name` | Mock user's given/first name |
| `family_name` | Mock user's family/last name |
| `groups` | Mock user's Cognito groups for authorisation testing |

See `dev-mock-user.example.json` in the repository for a complete template.

### Alternative Config Location

You can specify a custom path via environment variable:

```bash
export COGNITO_AUTH_DEV_CONFIG=/path/to/your/mock-user.json
```

!!! tip "Using gds-idea-app-kit?"
    Projects scaffolded with [gds-idea-app-kit](https://github.com/co-cddo/gds-idea-app-kit) come with dev mocks pre-configured in `dev_mocks/` and the `COGNITO_AUTH_DEV_CONFIG` environment variable already set in the dev container.

## Mock Users in Tests

For unit tests, use `User.create_mock()` directly without needing dev mode:

```python
from cognito_auth import User

# With defaults
user = User.create_mock()

# With custom values
user = User.create_mock(
    email="test@example.com",
    name="Test User",
    groups=["admin"],
)

assert user.is_authenticated is True
assert user.name == "Test User"
```

See [User.create_mock()](api/user.md) for all available parameters.

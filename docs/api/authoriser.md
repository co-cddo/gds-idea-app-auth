# Authorizer

The `Authorizer` class provides flexible authorisation rules for controlling access to your application.

::: cognito_auth.authoriser.Authorizer
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - from_lists
        - from_config
        - clear_config_cache
        - is_authorised

## Authorisation Rules

### GroupRule

::: cognito_auth.authoriser.GroupRule
    options:
      show_root_heading: true
      members:
        - __init__
        - is_allowed

### EmailRule

::: cognito_auth.authoriser.EmailRule
    options:
      show_root_heading: true
      members:
        - __init__
        - is_allowed

## Examples

### Basic Usage

```python
from cognito_auth import Authoriser, User

# Allow specific groups
authorizer = Authoriser.from_lists(
    allowed_groups=["developers", "admins"]
)

user = User.create_mock(groups=["developers"])
assert authorizer.is_authorised(user) is True
```

### OR Logic (Default)

By default, user must match ANY rule:

```python
authorizer = Authoriser.from_lists(
    allowed_groups=["developers"],
    allowed_users=["special@example.com"],
    require_all=False  # Default
)

# User passes if they're in "developers" OR have email "special@example.com"
```

### AND Logic

Require user to match ALL rules:

```python
authorizer = Authoriser.from_lists(
    allowed_groups=["developers"],
    allowed_users=["admin@example.com"],
    require_all=True
)

# User must be in "developers" AND have email "admin@example.com"
```

### Loading from Configuration

```python
# From local file (development)
import os
os.environ["COGNITO_AUTH_CONFIG_PATH"] = "./auth-config.json"
authorizer = Authoriser.from_config()

# From AWS Secrets Manager (production)
os.environ["COGNITO_AUTH_SECRET_NAME"] = "my-app/auth-config"
authorizer = Authoriser.from_config()
```

## Configuration File Format

Create `auth-config.json`:

```json
{
  "allowed_groups": ["developers", "admins", "users"],
  "allowed_users": ["special-user@example.com"],
  "require_all": false
}
```

See `auth-config.example.json` for a complete template.

## Caching

Authorisation config loaded via `from_config()` is cached for 5 minutes (300 seconds). To force a reload:

```python
Authoriser.clear_config_cache()
```

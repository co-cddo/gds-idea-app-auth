# Authorizer

The `Authorizer` class provides flexible authorization rules for controlling access to your application.

::: cognito_auth.authorizer.Authorizer
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - from_lists
        - from_config
        - clear_config_cache
        - is_authorized

## Authorization Rules

### GroupRule

::: cognito_auth.authorizer.GroupRule
    options:
      show_root_heading: true
      members:
        - __init__
        - is_allowed

### EmailRule

::: cognito_auth.authorizer.EmailRule
    options:
      show_root_heading: true
      members:
        - __init__
        - is_allowed

## Examples

### Basic Usage

```python
from cognito_auth import Authorizer, User

# Allow specific groups
authorizer = Authorizer.from_lists(
    allowed_groups=["developers", "admins"]
)

user = User.create_mock(groups=["developers"])
assert authorizer.is_authorized(user) is True
```

### OR Logic (Default)

By default, user must match ANY rule:

```python
authorizer = Authorizer.from_lists(
    allowed_groups=["developers"],
    allowed_users=["special@example.com"],
    require_all=False  # Default
)

# User passes if they're in "developers" OR have email "special@example.com"
```

### AND Logic

Require user to match ALL rules:

```python
authorizer = Authorizer.from_lists(
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
authorizer = Authorizer.from_config()

# From AWS Secrets Manager (production)
os.environ["COGNITO_AUTH_SECRET_NAME"] = "my-app/auth-config"
authorizer = Authorizer.from_config()
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

Authorization config loaded via `from_config()` is cached for 5 minutes (300 seconds). To force a reload:

```python
Authorizer.clear_config_cache()
```

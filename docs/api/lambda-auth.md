# LambdaAuth

Authentication for AWS Lambda functions behind an Application Load Balancer.

::: cognito_auth.lambda_auth.LambdaAuth
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - get_auth_user

## Quick Start

```python
from cognito_auth.lambda_auth import LambdaAuth
from cognito_auth import Authoriser

authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = LambdaAuth(authoriser=authoriser)

def handler(event, context):
    try:
        user = auth.get_auth_user(event)
    except Exception:
        return {
            "statusCode": 302,
            "headers": {"Location": auth.redirect_url},
            "body": "",
        }

    return {
        "statusCode": 200,
        "body": f"Hello {user.email}!",
    }
```

## Configuration

LambdaAuth inherits from BaseAuth and accepts these parameters:

- **`authoriser`** (optional): Pre-configured Authoriser instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorised users (default: "https://public.gds-idea.io/401.html"). Available as `auth.redirect_url` for building redirect responses.
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authoriser
from cognito_auth.lambda_auth import LambdaAuth

# Custom configuration
authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = LambdaAuth(
    authoriser=authoriser,
    redirect_url="https://myapp.com/unauthorised",
    region="us-east-1"
)
```

## Behavior

LambdaAuth extracts OIDC headers from the ALB Lambda event and verifies them. On failure:

- **`MissingTokenError`**: Required OIDC headers not present in the event
- **`InvalidTokenError`**: Token verification failed
- **`ExpiredTokenError`**: Token has expired
- **`PermissionError`**: User authenticated but not authorised

The caller is responsible for building the appropriate Lambda response (redirect, JSON error, etc.).

## Development Mode

Enable dev mode for local development without ALB. See [Development Mode](../dev-mode.md) for full details.

```bash
export COGNITO_AUTH_DEV_MODE=true
```

## Complete Example

```python
from cognito_auth.lambda_auth import LambdaAuth
from cognito_auth import Authoriser

authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = LambdaAuth(authoriser=authoriser)

def handler(event, context):
    try:
        user = auth.get_auth_user(event)
    except Exception:
        return {
            "statusCode": 302,
            "headers": {"Location": auth.redirect_url},
            "body": "",
        }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": f"""
            <h1>Welcome {user.name}!</h1>
            <p>Email: {user.email}</p>
            <p>Groups: {', '.join(user.groups)}</p>
        """,
    }
```

### No Authorisation (Authentication Only)

```python
from cognito_auth.lambda_auth import LambdaAuth

# Pass authoriser=None to skip authorisation checks
auth = LambdaAuth(authoriser=None)

def handler(event, context):
    try:
        user = auth.get_auth_user(event)
    except Exception:
        return {
            "statusCode": 302,
            "headers": {"Location": auth.redirect_url},
            "body": "",
        }

    return {
        "statusCode": 200,
        "body": f"Authenticated as {user.email}",
    }
```

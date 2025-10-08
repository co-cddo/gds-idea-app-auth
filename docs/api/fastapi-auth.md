# FastAPIAuth

Authentication for FastAPI applications.

::: cognito_auth.fastapi.FastAPIAuth
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - protect_app
        - get_auth_user

## Quick Start

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()

# Auto-loads from environment variables
auth = FastAPIAuth()
auth.protect_app(app)  # Protects entire app!

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {"message": f"Welcome {user.email}!"}
```

## Configuration

FastAPIAuth inherits from BaseAuth and accepts these parameters:

- **`authoriser`** (optional): Pre-configured Authoriser instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorised users (default: "https://gds-idea.click/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authoriser
from cognito_auth.fastapi import FastAPIAuth

# Custom configuration
authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = FastAPIAuth(
    authoriser=authoriser,
    redirect_url="https://myapp.com/unauthorised",
    region="us-east-1"
)
```

## Behavior

FastAPIAuth uses dependency injection with `Depends()`. When authentication or authorisation fails:

- **With `protect_app()`**: Middleware redirects to `redirect_url` before any route executes
- **Without `protect_app()`**: Routes with `Depends(auth.get_auth_user)` raise `HTTPException` (401 for auth failure, 403 for unauthorised)

The user is stored in `request.state.user`, making it efficient to call `get_auth_user()` multiple times.

## Development Mode

Enable dev mode for local development without ALB:

```bash
export COGNITO_AUTH_DEV_MODE=true
```

When dev mode is enabled and headers are missing, `get_auth_user()` returns a mock user instead of failing.

### Customizing the Mock User

To customize the mock user returned in dev mode, create a `dev-mock-user.json` file in your project root:

```json
{
  "email": "developer@example.com",
  "sub": "12345678-1234-1234-1234-123456789abc",
  "username": "12345678-1234-1234-1234-123456789abc",
  "groups": ["developers", "users"]
}
```

The mock user will use these values instead of the defaults. This is useful for testing different authorisation scenarios.

**Available fields:**
- `email` - Mock user's email address
- `sub` - Mock user's Cognito subject (UUID)
- `username` - Mock user's username (usually same as sub)
- `groups` - Mock user's Cognito groups for authorisation testing

See `dev-mock-user.example.json` in the repository for a complete template with comments.

**Alternative config location:**

You can specify a custom path via environment variable:

```bash
export COGNITO_AUTH_DEV_CONFIG=/path/to/your/mock-user.json
```

## Complete Example

### Protect Entire App (Recommended)

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()

# Initialize and protect entire app
auth = FastAPIAuth()
auth.protect_app(app)

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {
        "message": f"Welcome {user.email}!",
        "groups": user.groups,
        "is_admin": user.is_admin
    }

@app.get("/admin")
def admin_only(user: User = Depends(auth.get_auth_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"message": "Admin panel"}
```

### Protect Specific Routes Only

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()
# Note: NOT calling protect_app()

@app.get("/public")
def public():
    return {"message": "Public endpoint"}

@app.get("/protected")
def protected(user: User = Depends(auth.get_auth_user)):
    return {"email": user.email}
```

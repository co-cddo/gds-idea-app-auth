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
    return {"message": f"Welcome {user.name}!"}
```

## Configuration

FastAPIAuth inherits from BaseAuth and accepts these parameters:

- **`authoriser`** (optional): Pre-configured Authoriser instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorised users (default: "https://gds-idea.io/401.html")
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

Enable dev mode for local development without ALB. See [Development Mode](../dev-mode.md) for full details.

```bash
export COGNITO_AUTH_DEV_MODE=true
```

## Complete Example

### Protect Entire App (Recommended)

```python
from fastapi import FastAPI, Depends, HTTPException
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()

# Initialize and protect entire app
auth = FastAPIAuth()
auth.protect_app(app)

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {
        "message": f"Welcome {user.name}!",
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

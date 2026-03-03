# cognito-auth

Unified authentication and authorisation for AWS Cognito-protected Python web applications.

## Features

- **Simple**: 2-3 lines of code to protect your entire app
- **Multi-framework**: Works with Streamlit, Dash, FastAPI, and Gradio
- **Flexible authorisation**: Group-based and email-based rules with AND/OR logic
- **Production-ready**: JWT token verification, caching, proper error handling
- **Dev mode**: Local development without ALB using mock users

## Prerequisites

This library handles **authentication and authorisation** for apps deployed behind AWS Application Load Balancer (ALB) with Cognito OIDC integration. It does not handle AWS infrastructure setup.

!!! tip "New project?"
    Use [gds-idea-app-kit](https://github.com/co-cddo/gds-idea-app-kit) to scaffold a complete project with AWS CDK infrastructure, dev containers, and pre-configured authentication:

    ```bash
    idea-app init streamlit my-app
    ```

    This sets up everything -- infrastructure, auth config, dev mocks, and a working app template. You can skip the installation and configuration sections below.

If integrating into an existing project, you need:

- An app deployed behind **AWS ALB** with **Cognito User Pool** OIDC authentication configured
- Python 3.12+

## Installation

Available extras: `streamlit`, `dash`, `fastapi`, `gradio`, `all`

```bash
# pip (preferred)
pip install "cognito-auth[streamlit] @ git+https://github.com/co-cddo/gds-idea-app-auth.git"

# uv
uv add cognito-auth[streamlit] --git https://github.com/co-cddo/gds-idea-app-auth.git
```

## Configuration

### Authorisation Rules

Create `auth-config.json` to define who can access your app:

```json
{
  "allowed_groups": ["developers", "admins"],
  "allowed_users": ["special@example.com"],
  "require_all": false
}
```

- `allowed_groups`: Cognito groups that are permitted access
- `allowed_users`: Specific email addresses permitted access
- `require_all`: `false` = user matches ANY rule (OR logic), `true` = user must match ALL rules (AND logic)

Then point your app at the config via an environment variable:

```bash
# Development (local file)
export COGNITO_AUTH_CONFIG_PATH=./auth-config.json

# Production (AWS Secrets Manager)
export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
```

For production, `COGNITO_AUTH_SECRET_NAME` should be the name of a secret in AWS Secrets Manager containing the JSON above. The auth class fetches it automatically.

See [Authoriser](api/authoriser.md) for advanced configuration (custom rules, AND/OR logic, caching).

## Quick Start

Your auth class handles both authentication (token verification) and authorisation (rule checking) automatically. You don't need to configure the `Authoriser` separately -- it loads from the config above.

### Streamlit

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

auth = StreamlitAuth()
user = auth.get_auth_user()

st.write(f"Welcome {user.name}!")
st.write(f"Groups: {', '.join(user.groups)}")
```

### FastAPI

Two patterns are available -- **protect the entire app** or **protect specific routes only**:

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()
auth.protect_app(app)  # Protects entire app

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {"message": f"Welcome {user.name}!"}
```

```python
# Or protect specific routes only (no protect_app call):
@app.get("/protected")
def protected(user: User = Depends(auth.get_auth_user)):
    return {"email": user.email}

@app.get("/public")
def public():
    return {"message": "No auth required"}
```

### Dash

```python
from dash import Dash
from cognito_auth.dash import DashAuth

app = Dash(__name__)
auth = DashAuth()
auth.protect_app(app)  # Protects entire app

@app.callback(...)
def my_callback(...):
    user = auth.get_auth_user()
    return f"Welcome {user.name}!"
```

### Using the User Object

Once authenticated, the `User` object provides useful properties:

```python
user.name           # "David Gillespie"
user.given_name     # "David"
user.family_name    # "Gillespie"
user.email          # "david.gillespie@example.com"
user.email_domain   # "example.com"
user.groups         # ["developers", "admins"]
user.is_admin       # True if in "gds-idea" group

if user.is_admin:
    show_admin_panel()
else:
    show_user_dashboard()
```

See [User](api/user.md) for the full list of properties.

## How It Works

```
AWS ALB + Cognito
    | (authenticates user, adds OIDC headers)
    v
Your App
    | (uses cognito-auth)
    v
Framework Auth Class (StreamlitAuth, DashAuth, FastAPIAuth, GradioAuth)
    | (validates JWT tokens, checks authorisation rules)
    v
User object --> Your code
```

1. **AWS ALB** authenticates users via Cognito and adds OIDC headers to every request
2. **cognito-auth** validates the JWT tokens (signature + expiry) and extracts user information
3. **Authorisation rules** from your config are checked (groups, emails, AND/OR logic)
4. Your app receives an authenticated `User` object with name, email, groups, etc.

Framework auth classes handle failures automatically -- Streamlit calls `st.stop()`, FastAPI raises `HTTPException`, Dash/Gradio redirect to a configurable URL.

## Development Mode

For local development without ALB, enable dev mode to use mock users:

```bash
export COGNITO_AUTH_DEV_MODE=true
```

See [Development Mode](dev-mode.md) for full details on configuring mock users.

## Resources

- [GitHub Repository](https://github.com/co-cddo/gds-idea-app-auth)
- [gds-idea-app-kit](https://github.com/co-cddo/gds-idea-app-kit) -- CLI tool for scaffolding new projects
- [API Reference](api/user.md)

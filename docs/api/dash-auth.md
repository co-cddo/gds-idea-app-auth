# DashAuth

Authentication for Dash and Flask applications.

::: cognito_auth.dash.DashAuth
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - protect_app
        - get_auth_user
        - require_auth

## Quick Start

```python
from dash import Dash
from cognito_auth.dash import DashAuth

app = Dash(__name__)

# Auto-loads from environment variables
auth = DashAuth()
auth.protect_app(app)  # Protects entire app!

@app.callback(...)
def my_callback(...):
    user = auth.get_auth_user()
    return f"Welcome {user.email}!"
```

## Configuration

DashAuth inherits from BaseAuth and accepts these parameters:

- **`authorizer`** (optional): Pre-configured Authorizer instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorized users (default: "https://gds-idea.click/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authorizer
from cognito_auth.dash import DashAuth

# Custom configuration
authorizer = Authorizer.from_lists(allowed_groups=["developers"])
auth = DashAuth(
    authorizer=authorizer,
    redirect_url="https://myapp.com/unauthorized",
    region="us-east-1"
)
```

## Behavior

Since Dash runs on Flask, DashAuth uses Flask's request handling. When authentication or authorization fails:

- **With `protect_app()`**: Automatically redirects to `redirect_url` before any callback executes
- **With `@require_auth` decorator**: Redirects to `redirect_url` for that specific route
- **With `get_auth_user()` only**: Raises `PermissionError` (useful in callbacks where you can't redirect)

The user is stored in Flask's `g.user` object, making it efficient to call `get_auth_user()` multiple times.

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

The mock user will use these values instead of the defaults. This is useful for testing different authorization scenarios.

**Available fields:**
- `email` - Mock user's email address
- `sub` - Mock user's Cognito subject (UUID)
- `username` - Mock user's username (usually same as sub)
- `groups` - Mock user's Cognito groups for authorization testing

See `dev-mock-user.example.json` in the repository for a complete template with comments.

**Alternative config location:**

You can specify a custom path via environment variable:

```bash
export COGNITO_AUTH_DEV_CONFIG=/path/to/your/mock-user.json
```

## Complete Example

### Dash Application

```python
from dash import Dash, html, dcc
from cognito_auth.dash import DashAuth

app = Dash(__name__)

# Initialize and protect entire app
auth = DashAuth()
auth.protect_app(app)

app.layout = html.Div([
    html.H1("Protected Dashboard"),
    html.Div(id="user-info"),
])

@app.callback(
    Output("user-info", "children"),
    Input("some-input", "value")
)
def display_user_info(value):
    user = auth.get_auth_user()

    return html.Div([
        html.P(f"Logged in as: {user.email}"),
        html.P(f"Admin: {'Yes' if user.is_admin else 'No'}"),
        html.Ul([html.Li(group) for group in user.groups])
    ])

if __name__ == "__main__":
    app.run_server(debug=True)
```

### Flask Application

```python
from flask import Flask
from cognito_auth.dash import DashAuth

app = Flask(__name__)

# Initialize and protect entire app
auth = DashAuth()
auth.protect_app(app)

@app.route("/")
def index():
    user = auth.get_auth_user()
    return f"<h1>Welcome {user.email}!</h1>"

@app.route("/admin")
def admin():
    user = auth.get_auth_user()
    if not user.is_admin:
        return "Access denied", 403
    return "<h1>Admin Panel</h1>"

if __name__ == "__main__":
    app.run(debug=True)
```

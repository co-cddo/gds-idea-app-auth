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
    return f"Welcome {user.name}!"
```

## Configuration

DashAuth inherits from BaseAuth and accepts these parameters:

- **`authoriser`** (optional): Pre-configured Authoriser instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorised users (default: "https://public.gds-idea.io/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authoriser
from cognito_auth.dash import DashAuth

# Custom configuration
authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = DashAuth(
    authoriser=authoriser,
    redirect_url="https://myapp.com/unauthorised",
    region="us-east-1"
)
```

## Behavior

Since Dash runs on Flask, DashAuth uses Flask's request handling. When authentication or authorisation fails:

- **With `protect_app()`**: Automatically redirects to `redirect_url` before any callback executes
- **With `@require_auth` decorator**: Redirects to `redirect_url` for that specific route
- **With `get_auth_user()` only**: Raises `PermissionError` (useful in callbacks where you can't redirect)

The user is stored in Flask's `g.user` object, making it efficient to call `get_auth_user()` multiple times.

!!! note "Flask support"
    DashAuth also works with standalone Flask applications. Pass a Flask `app` to `protect_app()` instead of a Dash `app`. See the Flask example below.

## Development Mode

Enable dev mode for local development without ALB. See [Development Mode](../dev-mode.md) for full details.

```bash
export COGNITO_AUTH_DEV_MODE=true
```

## Complete Example

### Dash Application

```python
import json

from dash import Dash, Input, Output, dcc, html
from cognito_auth.dash import DashAuth

app = Dash(__name__)

# Initialize and protect entire app
auth = DashAuth()
auth.protect_app(app)

app.layout = html.Div([
    html.H1("Protected Dashboard"),
    html.Div(id="user-info"),
    # Interval triggers initial load
    dcc.Interval(id="interval", interval=1000, n_intervals=0, max_intervals=1),
])

@app.callback(
    Output("user-info", "children"),
    Input("interval", "n_intervals"),
)
def display_user_info(n):
    user = auth.get_auth_user()

    return html.Div([
        html.P(f"Logged in as: {user.name} ({user.email})"),
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
    return f"<h1>Welcome {user.name}!</h1>"

@app.route("/admin")
def admin():
    user = auth.get_auth_user()
    if not user.is_admin:
        return "Access denied", 403
    return "<h1>Admin Panel</h1>"

if __name__ == "__main__":
    app.run(debug=True)
```

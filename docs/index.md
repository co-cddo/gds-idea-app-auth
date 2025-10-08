# cognito-auth

AWS Cognito authentication for Python web frameworks with comprehensive support for Streamlit, Dash, FastAPI, Flask, and Gradio.

## Features

- ✅ **Simple**: 2-3 lines of code to protect your entire app
- ✅ **Multi-framework**: Works with Streamlit, Dash, Flask, FastAPI, and Gradio
- ✅ **Flexible authorisation**: Group-based and email-based rules with AND/OR logic
- ✅ **Production-ready**: JWT token verification, caching, proper error handling
- ✅ **Dev mode**: Local development without ALB using mock users

## Installation

The package requires **Python 3.12+**. Install for your specific framework:

```bash
# Streamlit
pip install cognito-auth[streamlit]

# Dash/Flask
pip install cognito-auth[dash]

# FastAPI
pip install cognito-auth[fastapi]

# Gradio
pip install cognito-auth[gradio]

# All frameworks
pip install cognito-auth[all]
```

## Framework Integration

### Streamlit

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

# Create auth handler
auth = StreamlitAuth()

# Get authenticated user
user = auth.get_auth_user()

# Your app code
st.title("Protected Streamlit App")
st.write(f"Welcome {user.email}!")
st.write(f"Your groups: {', '.join(user.groups)}")

# Access control based on groups
if "admin" in user.groups:
    st.write("Admin content here")
```

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth
from cognito_auth.exceptions import AuthorisationError

app = FastAPI()
auth = FastAPIAuth()

# Protect all routes
auth.protect_app(app)

# Error handling
@app.exception_handler(AuthorisationError)
async def auth_error_handler(request, exc):
    return JSONResponse(
        status_code=403,
        content={"error": str(exc)}
    )

# Protected route with dependency injection
@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {
        "message": f"Welcome {user.email}!",
        "groups": user.groups
    }

# Group-based access control
@app.get("/admin")
def admin_only(user: User = Depends(auth.get_auth_user)):
    if "admin" not in user.groups:
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"message": "Admin dashboard"}
```

### Dash

```python
from dash import Dash, html, dcc, Output, Input, callback_context
import flask
from cognito_auth.dash import DashAuth

# Create your app
app = Dash(__name__)
server = app.server  # Flask server
auth = DashAuth()

# Protect the app
auth.protect_app(app)

# Define layout
app.layout = html.Div([
    html.H1("Protected Dash App"),
    html.Div(id="user-info"),
    dcc.Location(id="url", refresh=False)
])

# Callbacks
@app.callback(
    Output("user-info", "children"),
    Input("url", "pathname")
)
def display_user_info(_):
    user = auth.get_auth_user()
    return [
        html.P(f"Logged in as: {user.email}"),
        html.P(f"Groups: {', '.join(user.groups)}")
    ]

# Run the app
if __name__ == "__main__":
    app.run_server(debug=True)
```

### Gradio

```python
import gradio as gr
from cognito_auth.gradio import GradioAuth

# Create auth handler
auth = GradioAuth()

# Define app functionality
def greet(name):
    user = auth.get_current_user()
    return f"Hello {name}! You're logged in as {user.email}"

# Create your app
demo = gr.Interface(
    fn=greet,
    inputs=gr.Textbox(label="Your name"),
    outputs=gr.Textbox(label="Greeting")
)

# Protect your app
auth.protect_app(demo)

# Launch the app
if __name__ == "__main__":
    demo.launch()
```

## Configuration

### Authentication Rules

Create an `auth-config.json` file:

```json
{
  "allowed_groups": ["developers", "admins"],
  "allowed_users": ["special@example.com"],
  "require_all": false
}
```

The configuration supports these options:

| Option | Type | Description |
|--------|------|-------------|
| `allowed_groups` | string[] | List of allowed Cognito groups |
| `allowed_users` | string[] | List of allowed email addresses |
| `allowed_domains` | string[] | List of allowed email domains |
| `require_all` | boolean | If true, user must match ALL conditions instead of ANY |

### Configuration Sources

Set the environment variable to specify where to load the config from:

```bash
# Local file
export COGNITO_AUTH_CONFIG_PATH=./auth-config.json

# AWS Secrets Manager
export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `COGNITO_AUTH_DEV_MODE` | Enable development mode | `false` | No |
| `COGNITO_AUTH_CONFIG_PATH` | Path to auth config file | None | No* |
| `COGNITO_AUTH_SECRET_NAME` | AWS Secret name for config | None | No* |
| `COGNITO_AUTH_MOCK_USER_PATH` | Path to mock user config | None | No |
| `COGNITO_AUTH_ADMIN_GROUP` | Group name for admin users | `gds-idea` | No |

\* Either `CONFIG_PATH` or `SECRET_NAME` is required in production mode

### Development Mode

For local development without AWS ALB:

```bash
export COGNITO_AUTH_DEV_MODE=true
```

Customize the mock user with `dev-mock-user.json`:

```json
{
  "email": "developer@example.com",
  "groups": ["developers", "admin"],
  "email_verified": true
}
```

## How It Works

### Architecture

```
┌─────────────────┐
│ AWS ALB+Cognito │
└────────┬────────┘
         │ OIDC Headers
         ▼
┌─────────────────┐
│    Your App     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Framework Auth  │  (StreamlitAuth, DashAuth, etc.)
└────────┬────────┘
         │ JWT Verification
         ▼
┌─────────────────┐
│  User Object    │  (email, groups, etc.)
└─────────────────┘
```

### Authentication Flow

1. **User Authentication**
   - User logs in via AWS Cognito
   - ALB adds OIDC headers to requests

2. **Token Verification**
   - Auth class extracts and validates JWT tokens
   - JWT signature is verified
   - Claims are extracted (email, groups, etc.)

3. **Authorization**
   - User is checked against configured rules
   - Access is granted or denied based on groups/email

4. **Integration**
   - Framework integration handles redirects and errors
   - Your app code receives authenticated User object

## User Object

The `User` object contains all authenticated user information:

```python
# Example user properties
user = auth.get_auth_user()

user.email           # "user@example.com"
user.groups          # ["developers", "admin"]
user.is_authenticated # True
user.is_admin        # True if in admin group
user.email_verified  # True if email verified in Cognito
user.email_domain    # "example.com"
user.sub             # UUID from Cognito
user.exp             # Token expiration timestamp
```

## Error Handling

Each framework has specific error handling mechanisms for authentication failures:

- **Streamlit**: Shows error page with customizable message
- **FastAPI**: Raises exception, handle with exception_handler
- **Dash**: Redirects to error page
- **Gradio**: Shows error message

See the [API Reference](api/) for framework-specific error handling.

## Troubleshooting

### Common Issues

- **No OIDC Headers**: Check ALB configuration and ensure Cognito is set up correctly
- **Token Verification Errors**: Ensure AWS region is correct and time is in sync
- **Unauthorized Access**: Check user groups and auth-config.json settings
- **Development Mode Issues**: Verify COGNITO_AUTH_DEV_MODE is set properly

### Debug Logging

Enable debug logging to troubleshoot issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## API Reference

- [User](api/user.md) - User object and mock creation
- [Authoriser](api/authoriser.md) - Authorization rules
- [StreamlitAuth](api/streamlit-auth.md) - Streamlit integration
- [DashAuth](api/dash-auth.md) - Dash/Flask integration
- [FastAPIAuth](api/fastapi-auth.md) - FastAPI integration
- [GradioAuth](api/gradio-auth.md) - Gradio integration
- [Exceptions](api/exceptions.md) - Error handling
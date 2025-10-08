# cognito-auth

Unified authentication and authorisation for AWS Cognito-protected web applications. Supports Streamlit, Dash, FastAPI, and Gradio with minimal configuration.

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- ✅ **Simple**: 2-3 lines of code to protect your entire app
- ✅ **Multi-framework**: Works with Streamlit, Dash, Flask, FastAPI, and Gradio
- ✅ **Flexible authorisation**: Group-based and email-based rules with AND/OR logic
- ✅ **Production-ready**: JWT token verification, caching, proper error handling
- ✅ **Dev mode**: Local development without ALB using mock users

## Installation

The package requires **Python 3.12 or newer**. Install the version specific to your framework:

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

## Quick Start

### Streamlit

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

# Create auth handler
auth = StreamlitAuth()

# Get authenticated user
user = auth.get_auth_user()

# Use user information
st.write(f"Welcome {user.email}!")
st.write(f"Your groups: {', '.join(user.groups)}")
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()

# Protect all routes
auth.protect_app(app)

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {
        "message": f"Welcome {user.email}!",
        "groups": user.groups
    }
```

### Dash

```python
from dash import Dash, html, Output, Input
from cognito_auth.dash import DashAuth

app = Dash(__name__)
auth = DashAuth()

# Protect the app
auth.protect_app(app)

app.layout = html.Div([
    html.H1("Protected Dash App"),
    html.Div(id="user-info")
])

@app.callback(
    Output("user-info", "children"),
    Input("url", "pathname")
)
def display_user_info(_):
    user = auth.get_auth_user()
    return f"Logged in as: {user.email}"

if __name__ == "__main__":
    app.run_server(debug=True)
```

### Gradio

```python
import gradio as gr
from cognito_auth.gradio import GradioAuth

def greet(name):
    return f"Hello, {name}!"

# Create and protect your app
auth = GradioAuth()
demo = gr.Interface(fn=greet, inputs="text", outputs="text")
auth.protect_app(demo)

# Launch the app
demo.launch()
```

## Configuration

### Authentication Configuration

Create an `auth-config.json` file:

```json
{
  "allowed_groups": ["developers", "admins"],
  "allowed_users": ["special@example.com"],
  "require_all": false
}
```

Set the environment variable:

```bash
# Development
export COGNITO_AUTH_CONFIG_PATH=./auth-config.json

# Production (AWS Secrets Manager)
export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `COGNITO_AUTH_DEV_MODE` | Enable development mode | `false` | No |
| `COGNITO_AUTH_CONFIG_PATH` | Path to auth config file | None | No* |
| `COGNITO_AUTH_SECRET_NAME` | AWS Secret name for config | None | No* |
| `COGNITO_AUTH_MOCK_USER_PATH` | Path to mock user config | None | No |

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
  "groups": ["developers", "admin"]
}
```

## Architecture

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

1. AWS ALB authenticates users via Cognito and adds OIDC headers
2. Your app initializes the appropriate Auth class
3. Auth class verifies JWT tokens and extracts user information
4. You receive a validated User object with email, groups, etc.

## Error Handling

Each framework has specific error handling mechanisms:

```python
# FastAPI example
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from cognito_auth.exceptions import AuthorisationError
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()

@app.exception_handler(AuthorisationError)
async def auth_error_handler(request, exc):
    return JSONResponse(
        status_code=403,
        content={"error": str(exc)}
    )
```

## Documentation

Full documentation available at [GitHub Pages](https://co-cddo.github.io/gds-idea-app-auth).

API Reference:
- [User](https://co-cddo.github.io/gds-idea-app-auth/api/user/)
- [StreamlitAuth](https://co-cddo.github.io/gds-idea-app-auth/api/streamlit-auth/)
- [DashAuth](https://co-cddo.github.io/gds-idea-app-auth/api/dash-auth/)
- [FastAPIAuth](https://co-cddo.github.io/gds-idea-app-auth/api/fastapi-auth/)
- [GradioAuth](https://co-cddo.github.io/gds-idea-app-auth/api/gradio-auth/)

## Contributing

### Setup

```bash
# Clone and install dependencies
git clone https://github.com/co-cddo/gds-idea-app-auth/
cd cognito-auth
uv sync
```

### Development Commands

- `uv run pytest` - Run tests
- `uv run pytest --cov` - Run tests with coverage
- `uv run ruff check .` - Lint code
- `uv run ruff format .` - Format code
- `uv run mkdocs serve` - Preview documentation locally

### Testing

Tests use pytest with fixtures and mocks. Add tests for new features in `tests/cognito_auth/`.

```bash
# Run specific test file
uv run pytest tests/cognito_auth/test_user.py -v

# Run tests matching pattern
uv run pytest -k test_authoriser
```

### Code Standards

- Python 3.12+
- Type hints where appropriate
- Ruff for linting and formatting (configured in `pyproject.toml`)
- 100% test coverage for new features

### Project Structure

```
src/cognito_auth/        # Main package
├── __init__.py          # Package exports
├── user.py              # User model
├── token_verifier.py    # JWT verification
├── authoriser.py        # Authorisation rules
├── _base_auth.py        # Base auth class
├── streamlit.py         # Streamlit integration
├── dash.py              # Dash/Flask integration
├── fastapi.py           # FastAPI integration
├── gradio.py            # Gradio integration
└── exceptions.py        # Custom exceptions

tests/cognito_auth/      # Test suite
docs/                    # MkDocs documentation
```

See `CLAUDE.md` for detailed architecture and development guidance.

## License

MIT License - see [LICENSE](LICENSE) for details.
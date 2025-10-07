# GradioAuth

Authentication for Gradio applications.

::: cognito_auth.gradio.GradioAuth
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - protect_app
        - get_auth_user

## Quick Start

### Standalone Gradio

```python
import gradio as gr
from cognito_auth.gradio import GradioAuth

auth = GradioAuth()

def greet(name: str, request: gr.Request):
    user = auth.get_auth_user(request)
    return f"Hello {name}! Logged in as {user.email}"

demo = gr.Interface(greet, "text", "text")
demo.launch()
```

### Gradio + FastAPI (Recommended)

```python
import gradio as gr
from fastapi import FastAPI
from cognito_auth.gradio import GradioAuth

app = FastAPI()
auth = GradioAuth()
auth.protect_app(app)  # Protects entire app!

def greet(name: str, request: gr.Request):
    user = auth.get_auth_user(request)
    return f"Hello {name}! Logged in as {user.email}"

demo = gr.Interface(greet, "text", "text")
app = gr.mount_gradio_app(app, demo, path="/")
```

## Configuration

GradioAuth inherits from BaseAuth and accepts these parameters:

- **`authorizer`** (optional): Pre-configured Authorizer instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorized users (default: "https://gds-idea.click/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authorizer
from cognito_auth.gradio import GradioAuth

# Custom configuration
authorizer = Authorizer.from_lists(allowed_groups=["developers"])
auth = GradioAuth(
    authorizer=authorizer,
    redirect_url="https://myapp.com/unauthorized",
    region="us-east-1"
)
```

## Behavior

GradioAuth works in two modes:

**Standalone Gradio:**
- User must be passed to `get_auth_user(request)` in each function
- Raises `PermissionError` on authorization failure

**Gradio + FastAPI with `protect_app()`:**
- Middleware redirects to `redirect_url` before Gradio functions execute
- User stored in `request.state.user` for efficiency

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

### Standalone Gradio

```python
import gradio as gr
from cognito_auth.gradio import GradioAuth

auth = GradioAuth()

def greet(name: str, request: gr.Request):
    user = auth.get_auth_user(request)

    info = f"""
    Hello {name}!

    Logged in as: {user.email}
    Groups: {', '.join(user.groups)}
    Admin: {'Yes' if user.is_admin else 'No'}
    """

    return info

demo = gr.Interface(
    fn=greet,
    inputs=gr.Textbox(label="Your Name"),
    outputs=gr.Textbox(label="Greeting")
)

demo.launch()
```

### Gradio + FastAPI

```python
import gradio as gr
from fastapi import FastAPI
from cognito_auth.gradio import GradioAuth

app = FastAPI()

# Initialize and protect entire app
auth = GradioAuth()
auth.protect_app(app)

def greet(name: str, request: gr.Request):
    user = auth.get_auth_user(request)

    return f"Hello {name}! Logged in as {user.email}"

def admin_panel(request: gr.Request):
    user = auth.get_auth_user(request)

    if not user.is_admin:
        return "⛔ Admin access required"

    return f"👑 Admin panel for {user.email}"

# Public interface
demo_public = gr.Interface(greet, "text", "text")

# Admin interface
demo_admin = gr.Interface(
    fn=admin_panel,
    inputs=None,
    outputs="text"
)

# Mount both interfaces
app = gr.mount_gradio_app(app, demo_public, path="/")
app = gr.mount_gradio_app(app, demo_admin, path="/admin")
```

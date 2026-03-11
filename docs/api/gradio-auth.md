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
    return f"Hello {name}! Logged in as {user.name}"

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
    return f"Hello {name}! Logged in as {user.name}"

demo = gr.Interface(greet, "text", "text")
app = gr.mount_gradio_app(app, demo, path="/")
```

## Configuration

GradioAuth inherits from BaseAuth and accepts these parameters:

- **`authoriser`** (optional): Pre-configured Authoriser instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Where to redirect unauthorised users (default: "https://gds-idea.io/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authoriser
from cognito_auth.gradio import GradioAuth

# Custom configuration
authoriser = Authoriser.from_lists(allowed_groups=["developers"])
auth = GradioAuth(
    authoriser=authoriser,
    redirect_url="https://myapp.com/unauthorised",
    region="us-east-1"
)
```

## Behavior

GradioAuth works in two modes:

**Standalone Gradio:**

- User must be passed to `get_auth_user(request)` in each function
- Raises `PermissionError` on authorisation failure

**Gradio + FastAPI with `protect_app()`:**

- Middleware redirects to `redirect_url` before Gradio functions execute
- User stored in `request.state.user` for efficiency

## Development Mode

Enable dev mode for local development without ALB. See [Development Mode](../dev-mode.md) for full details.

```bash
export COGNITO_AUTH_DEV_MODE=true
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

    Logged in as: {user.name} ({user.email})
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

    return f"Hello {name}! Logged in as {user.name}"

def admin_panel(request: gr.Request):
    user = auth.get_auth_user(request)

    if not user.is_admin:
        return "Admin access required"

    return f"Admin panel for {user.name}"

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

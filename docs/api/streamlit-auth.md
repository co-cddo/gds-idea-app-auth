# StreamlitAuth

Authentication for Streamlit applications.

::: cognito_auth.streamlit.StreamlitAuth
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - get_auth_user

## Quick Start

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

# Auto-loads from environment variables
auth = StreamlitAuth()
user = auth.get_auth_user()

st.write(f"Welcome {user.email}!")
st.write(f"Groups: {', '.join(user.groups)}")
```

## Configuration

StreamlitAuth inherits from BaseAuth and accepts these parameters:

- **`authorizer`** (optional): Pre-configured Authorizer instance. If not provided, auto-loads from environment variables
- **`redirect_url`** (optional): Not used in Streamlit (defaults to "https://gds-idea.click/401.html")
- **`region`** (optional): AWS region (default: "eu-west-2")

```python
from cognito_auth import Authoriser
from cognito_auth.streamlit import StreamlitAuth

# Custom configuration
authorizer = Authoriser.from_lists(allowed_groups=["developers"])
auth = StreamlitAuth(
    authoriser=authorizer,
    region="us-east-1"
)
```

## Behavior

Unlike other frameworks, Streamlit cannot redirect users. When authentication or authorisation fails, `get_auth_user()`:

1. Displays an error message using `st.error()`
2. Displays an info message using `st.info()`
3. Stops execution using `st.stop()`

This prevents any code after `get_auth_user()` from running for unauthorised users.

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

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

# Initialize auth
auth = StreamlitAuth()

# This line protects your entire app
user = auth.get_auth_user()

# Only authenticated and authorised users reach here
st.title("Protected Dashboard")
st.write(f"Logged in as: {user.email}")

# Use user information in your app
if user.is_admin:
    st.write("🔑 You have admin access")

for group in user.groups:
    st.write(f"📁 {group}")
```

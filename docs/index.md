# cognito-auth

AWS Cognito authentication for Python web frameworks (Streamlit, Dash, Flask, FastAPI, Gradio).

## Features

- ✅ **Simple**: 2-3 lines of code to protect your entire app
- ✅ **Multi-framework**: Works with Streamlit, Dash, Flask, FastAPI, and Gradio
- ✅ **Flexible authorisation**: Group-based and email-based rules with AND/OR logic
- ✅ **Production-ready**: JWT token verification, caching, proper error handling
- ✅ **Dev mode**: Local development without ALB using mock users

## Quick Start

Install for your framework:

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

### Example: Streamlit

```python
import streamlit as st
from cognito_auth.streamlit import StreamlitAuth

auth = StreamlitAuth()
user = auth.get_auth_user()

st.write(f"Welcome {user.email}!")
```

### Example: FastAPI

```python
from fastapi import FastAPI, Depends
from cognito_auth import User
from cognito_auth.fastapi import FastAPIAuth

app = FastAPI()
auth = FastAPIAuth()
auth.protect_app(app)

@app.get("/")
def index(user: User = Depends(auth.get_auth_user)):
    return {"message": f"Welcome {user.email}!"}
```

## How It Works

1. **AWS ALB** authenticates users via Cognito and adds OIDC headers to requests
2. **cognito-auth** validates JWT tokens and extracts user information
3. **Authoriser** checks if user meets your authorisation rules
4. Your app receives an authenticated `User` object with email, groups, etc.

## Architecture

```
AWS ALB + Cognito
    ↓ (adds OIDC headers)
Your App
    ↓ (uses cognito-auth)
Framework Auth Class (StreamlitAuth, DashAuth, etc.)
    ↓ (validates tokens)
User object → Your code
```

## Configuration

### Authorisation Rules

Create `auth-config.json`:

```json
{
  "allowed_groups": ["developers", "admins"],
  "allowed_users": ["special@example.com"],
  "require_all": false
}
```

Set environment variable:

```bash
# Development
export COGNITO_AUTH_CONFIG_PATH=./auth-config.json

# Production
export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
```

### Development Mode

For local development without ALB:

```bash
export COGNITO_AUTH_DEV_MODE=true
```

Optionally customize the mock user with `dev-mock-user.json`:

```json
{
  "email": "developer@example.com",
  "groups": ["developers", "admin"]
}
```

## Next Steps

- [Installation Guide](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Framework Guides](frameworks/streamlit.md)
- [API Reference](api/user.md)

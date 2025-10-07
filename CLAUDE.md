# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`cognito-auth` is a Python package providing unified authentication and authorisation for AWS Cognito-protected web applications. It supports multiple frameworks: Streamlit, Dash, FastAPI, and Gradio.

The package verifies JWT tokens from AWS Application Load Balancer (ALB) OIDC integration with Cognito User Pools and provides flexible authorisation rules based on email domains, Cognito groups, or specific users.

## Development Commands

### Package Management (uv)
This project uses `uv` for dependency management:
- `uv sync` - Install dependencies
- `uv add <package>` - Add a new dependency
- `uv add --dev <package>` - Add a dev dependency
- `uv pip list` - List installed packages

### Linting
- `uv run ruff check .` - Run linter
- `uv run ruff check . --fix` - Auto-fix linting issues
- `uv run ruff format .` - Format code

Ruff is configured in `pyproject.toml` with rules: E (Pycodestyle), F (Pyflakes), I (isort), B (Bugbear), UP (Pyupgrade), N (pep8-naming), A (flake8-builtins), PT (pytest style). Line length (E501) is ignored.

### Testing
- `uv run pytest` - Run all tests
- `uv run pytest tests/test_user.py` - Run specific test file
- `uv run pytest -v` - Run tests with verbose output
- `uv run pytest -k test_name` - Run tests matching pattern

Tests use pytest fixtures and mock User creation for isolation.

## Architecture

### Core Components

1. **User** (`user.py`)
   - Represents an authenticated user from AWS ALB + Cognito headers
   - Extracts and stores claims from both `x-amzn-oidc-data` (ALB) and `x-amzn-oidc-accesstoken` (Cognito) headers
   - Properties: `sub`, `username`, `email`, `email_domain`, `groups`, `is_authenticated`, `exp`, etc.
   - Always verify tokens in production (`verify_tokens=True`)

2. **TokenVerifier** (`token_verifier.py`)
   - Verifies JWT signatures for both ALB (ES256) and Cognito (RS256) tokens
   - Fetches public keys from AWS endpoints and caches them (default 1 hour TTL)
   - Raises `InvalidTokenError` or `ExpiredTokenError` on verification failure

3. **Authorizer** (`authorizer.py`)
   - Composable authorisation rules system using Protocol pattern
   - Built-in rules: `GroupRule`, `EmailRule`
   - `require_all=False` means ANY rule passes (OR logic)
   - `require_all=True` means ALL rules must pass (AND logic)
   - Can create custom rules by implementing `AuthorisationRule` protocol
   - Note: Domain-based authorisation is not needed as domains are used at signup to assign groups

4. **AuthGuard** (`guard.py`)
   - Unified interface for protecting apps across frameworks
   - Methods: `streamlit()`, `dash()`, `fastapi()`, `get_current_user_gradio()`, `gradio_middleware()`
   - Factory methods: `from_s3()`, `from_secrets()`, `from_parameter_store()`
   - Handles both authentication (token verification) and authorisation (rule checking)
   - Redirects to `redirect_url` on auth failure (default: https://gds-idea.click/401.html)

### Authentication Flow

1. ALB intercepts requests and adds OIDC headers after Cognito authentication
2. `AuthGuard` extracts headers via framework-specific methods
3. `User` is instantiated, which triggers `TokenVerifier` to verify both tokens
4. If tokens valid, `Authorizer` checks if user meets authorisation rules
5. If authorised, user object is returned; otherwise, redirect or raise exception

### Framework Integration Patterns

- **Streamlit**: Call `guard.streamlit()` at app start, uses `st.context.headers`
- **Dash**: Decorate app creation with `@guard.dash`, get user via `guard.get_current_user_dash()` in callbacks
- **FastAPI**: Use `Depends(guard.fastapi())` in route parameters
- **Gradio**: Use `guard.get_current_user_gradio(request)` in functions or `guard.gradio_middleware()` for FastAPI+Gradio apps

## Package Structure

```
src/cognito_auth/
├── __init__.py          # Public API: User, exceptions
├── user.py              # User model with token claims
├── token_verifier.py    # JWT verification logic
├── authorizer.py        # Authorisation rules engine
├── guard.py             # Framework-specific auth guards
├── exceptions.py        # Custom exceptions
└── helpers/             # Framework-specific helper utilities (empty currently)
```

## Configuration Management

The package supports seamless configuration loading for dev and production environments.

### Using from_config()

**Same code works in both environments:**
```python
from cognito_auth import AuthGuard

# Works in development AND production
guard = AuthGuard.from_config()
user = guard.streamlit()
```

### Configuration File Format

JSON structure for authorisation rules:
```json
{
  "allowed_groups": ["developers", "admins", "users"],
  "allowed_users": ["special-user@example.com"],
  "require_all": false
}
```

See `auth-config.example.json` for a template.

### Environment Variables

Requires **one** of these:

**Development (local file):**
```bash
export COGNITO_AUTH_CONFIG_PATH=./auth-config.json
```

**Production (AWS Secrets Manager):**
```bash
export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
```

### Validation

Config validation with Pydantic ensures:
- Email addresses are valid format
- At least one of `allowed_groups` or `allowed_users` is specified
- `require_all` is boolean
- Clear error messages for invalid configs

### Testing Config Loading

Tests located in `tests/cognito_auth/test_authorizer.py` cover:
- Loading from local files
- Loading from AWS Secrets (mocked)
- Email validation
- Invalid JSON handling
- Missing environment variables

## Development Mode (Local Development)

For local development without ALB/Cognito headers:

1. **Enable dev mode** via environment variable:
   ```bash
   export COGNITO_AUTH_DEV_MODE=true
   ```

2. **Configure mock user** (optional) by creating `dev-mock-user.json`:
   ```json
   {
     "email": "developer@example.com",
     "sub": "12345678-1234-1234-1234-123456789abc",
     "username": "12345678-1234-1234-1234-123456789abc",
     "groups": ["developers", "users"]
   }
   ```
   See `dev-mock-user.example.json` for template.

3. **Use AuthGuard normally** - it will automatically use mock users when headers are missing:
   ```python
   guard = AuthGuard(allowed_groups=['developers'])
   user = guard.streamlit()  # Returns mock user in dev mode
   ```

**Important:** Dev mode warnings are displayed via Python's `warnings` module. Never enable in production.

### Testing with Mock Users

Use `User.create_mock()` in tests:
```python
from cognito_auth import User

# With defaults
user = User.create_mock()

# With custom values
user = User.create_mock(
    email="test@example.com",
    groups=["admin"],
)
```

## Important Notes

- Requires Python 3.13+
- AWS region defaults to `eu-west-2` but is configurable
- In real Cognito tokens, `username` is a UUID (same as `sub`), so `email` is the primary human-readable identifier
- Authorisation is group-based only - domains are handled at signup to assign users to appropriate groups

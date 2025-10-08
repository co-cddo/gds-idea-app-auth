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

Ruff is configured in `pyproject.toml` with rules: E (Pycodestyle), F (Pyflakes), I (isort), B (Bugbear), UP (Pyupgrade), N (pep8-naming), A (flake8-builtins), PT (pytest style).

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

3. **Authoriser** (`authoriser.py`)
   - Composable authorisation rules system using Protocol pattern
   - Built-in rules: `GroupRule`, `EmailRule`
   - `require_all=False` means ANY rule passes (OR logic)
   - `require_all=True` means ALL rules must pass (AND logic)
   - Can create custom rules by implementing `AuthorisationRule` protocol
   - Note: Domain-based authorisation is not needed as domains are used at signup to assign groups

4. **Framework Auth Classes** (`_base_auth.py`, `streamlit.py`, `dash.py`, `fastapi.py`, `gradio.py`)
   - `_base_auth.py`: Base authentication class with common functionality
   - Separate auth classes for each framework (StreamlitAuth, DashAuth, FastAPIAuth, GradioAuth)
   - Factory methods: `from_config()` (auto-detects local file vs AWS Secrets Manager)
   - Handles both authentication (token verification) and authorisation (rule checking)
   - Redirects to `redirect_url` on auth failure (default: https://gds-idea.click/401.html)

### Authentication Flow

1. ALB intercepts requests and adds OIDC headers after Cognito authentication
2. Framework-specific auth class extracts headers via framework-specific methods
3. `User` is instantiated, which triggers `TokenVerifier` to verify both tokens
4. If tokens valid, `Authoriser` checks if user meets authorisation rules
5. If authorised, user object is returned; otherwise, redirect or raise exception

### Framework Integration Patterns

- **Streamlit**: Instantiate `StreamlitAuth` and call `get_auth_user()` at app start, uses `st.context.headers`
- **Dash**: Instantiate `DashAuth` and use `@auth.require_auth` decorator on app creation, get user via `get_auth_user()` in callbacks
- **FastAPI**: Instantiate `FastAPIAuth` and use `Depends(auth.get_auth_user)` in route parameters
- **Gradio**: Instantiate `GradioAuth` and use `get_auth_user(request)` in functions or apply via middleware

## Package Structure

```
src/cognito_auth/
├── __init__.py          # Public API: User, Authoriser, exceptions
├── user.py              # User model with token claims
├── token_verifier.py    # JWT verification logic
├── authoriser.py        # Authorisation rules engine
├── _base_auth.py        # Base authentication class
├── streamlit.py         # Streamlit auth integration
├── dash.py              # Dash auth integration
├── fastapi.py           # FastAPI auth integration
├── gradio.py            # Gradio auth integration
└── exceptions.py        # Custom exceptions
```

## Configuration Management

The package supports seamless configuration loading for dev and production environments.

### Using from_config()

**Same code works in both environments:**
```python
from cognito_auth.streamlit import StreamlitAuth

# Works in development AND production
auth = StreamlitAuth.from_config()
user = auth.get_auth_user()
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

Tests located in `tests/cognito_auth/test_authoriser.py` cover:
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

3. **Use auth classes normally** - they will automatically use mock users when headers are missing:
   ```python
   from cognito_auth.streamlit import StreamlitAuth

   auth = StreamlitAuth(allowed_groups=['developers'])
   user = auth.get_auth_user()  # Returns mock user in dev mode
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

- Requires Python 3.12+
- AWS region defaults to `eu-west-2` but is configurable
- In real Cognito tokens, `username` is a UUID (same as `sub`), so `email` is the primary human-readable identifier
- Authorisation is group-based only - domains are handled at signup to assign users to appropriate groups

## CI/CD

### GitHub Actions Workflows

The project includes two GitHub Actions workflows:

1. **PR Checks** (`.github/workflows/pr-checks.yml`)
   - Runs on PRs to main and dev branches
   - Checks version has been bumped in `pyproject.toml`
   - Runs linting (ruff check and format)
   - Tests on Python 3.12, 3.13, and 3.14
   - Builds documentation with `mkdocs build --strict`
   - Builds package with `uv build`

2. **Release** (`.github/workflows/release.yml`)
   - Runs on push to main branch
   - Builds and deploys documentation to GitHub Pages
   - Creates GitHub Release with auto-generated notes
   - Tags release with version from `pyproject.toml`
   - Attaches built package artifacts to release

**Important:** All PRs must bump the version in `pyproject.toml` or the PR checks will fail.

# AGENTS.md

Python package providing unified AWS Cognito authentication and authorisation for Streamlit, Dash, FastAPI, and Gradio applications. Verifies JWT tokens from AWS ALB OIDC integration with Cognito User Pools.

## Development Commands

This project uses `uv` for dependency management.

```bash
uv sync                        # Install dependencies
uv run ruff check .            # Lint
uv run ruff check . --fix      # Auto-fix lint issues
uv run ruff format .           # Format code
uv run pytest                  # Run all tests
uv run pytest -v               # Verbose test output
uv run pytest -k test_name     # Run tests matching pattern
uv run mkdocs serve            # Preview docs locally
```

Ruff is configured in `pyproject.toml` with rules: E, F, I, B, UP, N, A, PT.

## Package Structure

```
src/cognito_auth/
├── __init__.py          # Public API exports
├── user.py              # User model (claims from ALB + Cognito headers)
├── token_verifier.py    # JWT verification (ALB ES256, Cognito RS256)
├── authoriser.py        # Composable authorisation rules (GroupRule, EmailRule)
├── _base_auth.py        # Base auth class with shared logic
├── streamlit.py         # StreamlitAuth
├── dash.py              # DashAuth
├── fastapi.py           # FastAPIAuth
├── gradio.py            # GradioAuth
└── exceptions.py        # InvalidTokenError, ExpiredTokenError
```

## Key Architecture

- **Auth flow**: ALB adds OIDC headers -> framework auth class extracts headers -> `User` created with token verification -> `Authoriser` checks rules -> user returned or redirect to `redirect_url` (default: `https://gds-idea.io/401.html`)
- **Authoriser**: `require_all=False` = OR logic (any rule passes), `require_all=True` = AND logic (all must pass). Custom rules implement `AuthorisationRule` protocol.
- **Config loading**: `from_config()` factory auto-detects `COGNITO_AUTH_CONFIG_PATH` (local JSON) or `COGNITO_AUTH_SECRET_NAME` (AWS Secrets Manager). Config is cached with 5-min TTL.
- **Dev mode**: Set `COGNITO_AUTH_DEV_MODE=true` to bypass auth with mock users locally. Never enable in production.
- **Testing**: Use `User.create_mock()` for test fixtures. Tests are in `tests/cognito_auth/`.

## CI Requirements

All PRs must:
1. Bump the version in `pyproject.toml` (CI checks this)
2. Pass linting (`ruff check` and `ruff format`)
3. Pass tests on Python 3.12, 3.13, and 3.14
4. Build docs successfully (`mkdocs build --strict`)

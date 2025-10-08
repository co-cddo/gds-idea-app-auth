# cognito-auth

Unified authentication and authorisation for AWS Cognito-protected web applications. Supports Streamlit, Dash, FastAPI, and Gradio with minimal configuration.

## Installation

```bash
pip install cognito-auth[streamlit]  # or dash, fastapi, gradio, all
```

## Quick Start

```python
from cognito_auth import AuthGuard

guard = AuthGuard.from_config()
user = guard.streamlit()  # or dash(), fastapi(), etc.
```

## Documentation

Full documentation available at co-cddo.github.io/gds-idea-app-auth.

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

- Python 3.13+
- Type hints where appropriate
- Ruff for linting and formatting (configured in `pyproject.toml`)
- 100% test coverage for new features

### Project Structure

```
src/cognito_auth/        # Main package
├── user.py              # User model
├── token_verifier.py    # JWT verification
├── authoriser.py        # Authorisation rules
└── [framework].py       # Framework integrations

tests/cognito_auth/      # Test suite
docs/                    # MkDocs documentation
```

See `CLAUDE.md` for detailed architecture and development guidance.

## License

MIT License - see [LICENSE](LICENSE) for details.
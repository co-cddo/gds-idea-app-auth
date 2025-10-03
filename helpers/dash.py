"""
Simple authentication and authorization helper for Dash apps.
"""

from functools import wraps
from typing import Callable, Optional

from flask import redirect, request

from .cognito_authorizer import Authorizer
from .cognito_user import User


def require_auth(
    redirect_url: str = "https://gds-idea.click/401.html",
    allowed_domains: Optional[list[str]] = None,
    allowed_groups: Optional[list[str]] = None,
    allowed_users: Optional[list[str]] = None,
    authorizer: Optional[Authorizer] = None,
    region: str = "eu-west-2",
    require_all: bool = False,
):
    """
    Dash authentication and authorization decorator.

    Use this to protect your Dash callbacks or the entire app.

    Args:
        redirect_url: Where to redirect on auth failure
        allowed_domains: List of allowed email domains (e.g., ['company.com'])
        allowed_groups: List of allowed Cognito groups (e.g., ['admins'])
        allowed_users: List of allowed usernames or subs
        authorizer: Pre-configured Authorizer instance (overrides other auth params)
        region: AWS region
        require_all: If True, ALL rules must pass. If False, ANY rule can pass.

    Returns:
        Decorator function that checks auth before executing

    Examples:
        # Protect entire app in server.py or app.py
        from dash_auth import require_auth

        @require_auth(allowed_domains=['company.com'])
        def create_app():
            app = dash.Dash(__name__)
            # ... build your app
            return app

        app = create_app()
        server = app.server

        # Or protect specific callbacks
        @app.callback(...)
        @require_auth(allowed_groups=['admins'])
        def admin_callback(...):
            ...

        # Or use custom authorizer
        auth = Authorizer.from_s3('my-bucket', 'permissions.json')

        @require_auth(authorizer=auth)
        def create_app():
            ...
    """
    # Build authorizer if not provided
    if authorizer is None and any([allowed_domains, allowed_groups, allowed_users]):
        authorizer = Authorizer.from_lists(
            allowed_domains=allowed_domains,
            allowed_groups=allowed_groups,
            allowed_users=allowed_users,
            require_all=require_all,
        )

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Get Cognito headers from Flask request
                headers = request.headers
                user = User(
                    oidc_data_header=headers.get("X-Amzn-Oidc-Data"),
                    access_token_header=headers.get("X-Amzn-Oidc-Accesstoken"),
                    region=region,
                    verify_tokens=True,
                )

                # Check authentication
                if not user.is_authenticated:
                    return redirect(redirect_url)

                # Check authorization if authorizer exists
                if authorizer is not None and not authorizer.is_authorized(user):
                    return redirect(redirect_url)

                # All checks passed - execute the function
                return func(*args, **kwargs)

            except Exception as e:
                # Auth failed - redirect
                return redirect(redirect_url)

        return wrapper

    return decorator


def get_current_user(region: str = "eu-west-2") -> Optional[User]:
    """
    Get the current authenticated user from request headers.

    Args:
        region: AWS region

    Returns:
        User object if authenticated, None otherwise

    Example:
        user = get_current_user()
        if user:
            print(f"Current user: {user.email}")
    """
    try:
        headers = request.headers
        user = User(
            oidc_data_header=headers.get("X-Amzn-Oidc-Data"),
            access_token_header=headers.get("X-Amzn-Oidc-Accesstoken"),
            region=region,
            verify_tokens=True,
        )
        return user if user.is_authenticated else None
    except Exception:
        return None

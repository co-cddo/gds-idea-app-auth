"""
Dash and Flask authentication module.
"""

from functools import wraps

from dash import Dash
from flask import Flask, g, redirect, request

from ._base_auth import BaseAuth
from .user import User


class DashAuth(BaseAuth):
    """
    Authentication for Dash and Flask apps.

    Since Dash runs on Flask, this class works for both frameworks.

    RECOMMENDED: Use protect_app() to protect your entire application with one line.

    Example (Dash - RECOMMENDED):
        from dash import Dash
        from cognito_auth.dash import DashAuth

        app = Dash(__name__)
        auth = DashAuth()
        auth.protect_app(app)  # Protects entire app!

        @app.callback(...)
        def my_callback(...):
            user = auth.get_auth_user()
            return f"Welcome {user.email}!"

    Example (Flask - RECOMMENDED):
        from flask import Flask
        from cognito_auth.dash import DashAuth

        app = Flask(__name__)
        auth = DashAuth()
        auth.protect_app(app)  # Protects entire app!

        @app.route("/")
        def index():
            user = auth.get_auth_user()
            return f"Welcome {user.email}!"

    Alternative: Protect individual routes with @require_auth decorator.
    """

    def protect_app(self, app: Dash | Flask) -> None:
        """
        Protect the entire application with authentication.

        This is the RECOMMENDED approach. Call this once after creating your app,
        and all routes/callbacks will require authentication. Use get_auth_user()
        anywhere to access the authenticated user.

        Args:
            app: Dash or Flask application instance

        Example:
            app = Dash(__name__)
            auth = DashAuth()
            auth.protect_app(app)  # One line protects everything!

            @app.callback(...)
            def my_callback(...):
                user = auth.get_auth_user()
                return f"Hello {user.email}"
        """
        # Get the underlying Flask app (Dash.server or Flask app itself)
        flask_app = app.server if isinstance(app, Dash) else app

        @flask_app.before_request
        def _check_auth():
            """Validate authentication before every request."""
            try:
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)

                if not self._is_authorized(user):
                    return redirect(self.redirect_url)

                # Store user in request-scoped g object
                g.user = user

            except Exception:
                return redirect(self.redirect_url)

    def get_auth_user(self) -> User:
        """
        Get the authenticated and authorized user for this request.

        When using protect_app() (RECOMMENDED), this retrieves the user that was
        validated during the before_request hook.

        When using @require_auth decorator, this validates the user on-demand.

        Returns:
            Authenticated and authorized User

        Raises:
            RuntimeError: If called outside request context or before protect_app()

        Example:
            auth.protect_app(app)

            @app.callback(...)
            def my_callback(...):
                user = auth.get_auth_user()
                return f"Hello {user.email}"
        """
        # If protect_app() was used, user is stored in g
        if hasattr(g, "user"):
            return g.user

        # Otherwise, validate on-demand (for @require_auth decorator usage)
        if not request:
            raise RuntimeError(
                "get_auth_user() must be called within a request context"
            )

        headers = dict(request.headers)
        user = self._get_user_from_headers(headers)

        if not self._is_authorized(user):
            raise PermissionError(
                "Access denied. You don't have permission to access this resource."
            )

        return user

    def require_auth(self, func):
        """
        Decorator to protect individual Flask routes.

        NOTE: Using protect_app() is RECOMMENDED instead of this decorator.
        This is provided for cases where you need route-specific protection.

        Args:
            func: The function to protect

        Returns:
            Wrapped function that requires authentication

        Example:
            @app.route("/protected")
            @auth.require_auth
            def protected_route():
                user = auth.get_auth_user()
                return f"Hello {user.email}"
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)

                if not self._is_authorized(user):
                    return redirect(self.redirect_url)

                # Store user in g for get_auth_user() to retrieve
                g.user = user

                return func(*args, **kwargs)

            except Exception:
                return redirect(self.redirect_url)

        return wrapper

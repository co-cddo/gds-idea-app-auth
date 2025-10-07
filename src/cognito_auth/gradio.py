"""
Gradio authentication module.
"""

from fastapi import FastAPI
from gradio import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

from ._base_auth import BaseAuth
from .user import User


class GradioAuth(BaseAuth):
    """
    Authentication for Gradio apps.

    Gradio can run standalone or mounted on FastAPI. This class supports both.

    Example (Standalone Gradio):
        import gradio as gr
        from cognito_auth.gradio import GradioAuth

        auth = GradioAuth()

        def greet(name: str, request: gr.Request):
            user = auth.get_auth_user(request)
            return f"Hello {name}! Logged in as {user.email}"

        demo = gr.Interface(greet, "text", "text")
        demo.launch()

    Example (Gradio + FastAPI):
        import gradio as gr
        from fastapi import FastAPI
        from cognito_auth.gradio import GradioAuth

        app = FastAPI()
        auth = GradioAuth()
        auth.protect_app(app)  # Protect entire app!

        def greet(name: str, request: gr.Request):
            user = auth.get_auth_user(request)
            return f"Hello {name}! Logged in as {user.email}"

        demo = gr.Interface(greet, "text", "text")
        app = gr.mount_gradio_app(app, demo, path="/")
    """

    def protect_app(self, app: FastAPI) -> None:
        """
        Protect a FastAPI app that has Gradio mounted on it.

        Use this when mounting Gradio onto FastAPI. It adds middleware to
        validate authentication before every request.

        NOTE: This only works when Gradio is mounted on FastAPI. For standalone
        Gradio apps, use get_auth_user() in each function instead.

        Args:
            app: FastAPI application instance (before mounting Gradio)

        Example:
            app = FastAPI()
            auth = GradioAuth()
            auth.protect_app(app)

            def greet(name: str, request: gr.Request):
                user = auth.get_auth_user(request)
                return f"Hello {name} ({user.email})"

            demo = gr.Interface(greet, "text", "text")
            app = gr.mount_gradio_app(app, demo, path="/")
        """

        class AuthMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, auth_instance):
                super().__init__(app)
                self.auth = auth_instance

            async def dispatch(self, request, call_next):
                """Validate authentication before every request."""
                try:
                    headers = dict(request.headers)
                    user = self.auth._get_user_from_headers(headers)

                    if not self.auth._is_authorized(user):
                        return RedirectResponse(url=self.auth.redirect_url)

                    # Store user in request state
                    request.state.user = user

                    return await call_next(request)

                except Exception:
                    return RedirectResponse(url=self.auth.redirect_url)

        app.add_middleware(AuthMiddleware, auth_instance=self)

    def get_auth_user(self, request: Request) -> User:
        """
        Get the authenticated and authorized user for this request.

        For standalone Gradio: Validates user from request headers.
        For Gradio + FastAPI with protect_app(): Retrieves pre-validated user.

        Args:
            request: Gradio Request object (pass as parameter to your function)

        Returns:
            Authenticated and authorized User

        Raises:
            PermissionError: If user is not authorized
            Exception: If authentication fails

        Example (Standalone):
            def greet(name: str, request: gr.Request):
                user = auth.get_auth_user(request)
                return f"Hello {name} ({user.email})"

        Example (With FastAPI):
            auth.protect_app(app)

            def greet(name: str, request: gr.Request):
                user = auth.get_auth_user(request)
                return f"Hello {name} ({user.email})"
        """
        # If protect_app() was used, user is stored in request.state
        if hasattr(request, "state") and hasattr(request.state, "user"):
            return request.state.user

        # Otherwise, validate on-demand (standalone Gradio)
        headers = dict(request.headers)
        user = self._get_user_from_headers(headers)

        if not self._is_authorized(user):
            raise PermissionError(
                "Access denied. You don't have permission to access this resource."
            )

        return user

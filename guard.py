"""
Unified authentication guard for Streamlit, Dash, FastAPI, and Gradio apps.
"""

from functools import wraps
from typing import Callable, Optional

from cognito_authorizer import Authorizer

from .cognito_user import User


class AuthGuard:
    """
    Unified authentication and authorization guard for web apps.

    Create one AuthGuard instance and use it across your entire app.

    Examples:
        # Example 1: Simple domain check
        guard = AuthGuard(allowed_domains=['company.com'])

        # Example 2: From S3 config
        guard = AuthGuard.from_s3('my-bucket', 'permissions.json')

        # Example 3: From Streamlit secrets
        guard = AuthGuard.from_secrets()
    """

    def __init__(
        self,
        authorizer: Optional[Authorizer] = None,
        allowed_domains: Optional[list[str]] = None,
        allowed_groups: Optional[list[str]] = None,
        allowed_users: Optional[list[str]] = None,
        redirect_url: str = "https://gds-idea.click/401.html",
        region: str = "eu-west-2",
        require_all: bool = False,
    ):
        """
        Initialize the auth guard.

        Args:
            authorizer: Pre-configured Authorizer instance
            allowed_domains: List of allowed email domains
            allowed_groups: List of allowed Cognito groups
            allowed_users: List of allowed usernames or subs
            redirect_url: Where to redirect on auth failure
            region: AWS region
            require_all: If True, ALL rules must pass. If False, ANY rule passes.
        """
        self.redirect_url = redirect_url
        self.region = region

        # Build authorizer if not provided
        if authorizer is None and any([allowed_domains, allowed_groups, allowed_users]):
            self.authorizer = Authorizer.from_lists(
                allowed_domains=allowed_domains,
                allowed_groups=allowed_groups,
                allowed_users=allowed_users,
                require_all=require_all,
            )
        else:
            self.authorizer = authorizer

    @classmethod
    def from_s3(cls, bucket: str, key: str, **kwargs):
        """Create guard with authorizer from S3."""
        authorizer = Authorizer.from_s3(bucket, key)
        return cls(authorizer=authorizer, **kwargs)

    @classmethod
    def from_secrets(cls, **kwargs):
        """Create guard with authorizer from Streamlit secrets."""
        authorizer = Authorizer.from_secrets()
        return cls(authorizer=authorizer, **kwargs)

    @classmethod
    def from_parameter_store(cls, parameter_prefix: str, **kwargs):
        """Create guard with authorizer from AWS Parameter Store."""
        authorizer = Authorizer.from_parameter_store(parameter_prefix)
        return cls(authorizer=authorizer, **kwargs)

    def _get_user_from_headers(self, headers: dict) -> User:
        """Extract and validate user from Cognito headers."""
        return User(
            oidc_data_header=headers.get("X-Amzn-Oidc-Data")
            or headers.get("x-amzn-oidc-data"),
            access_token_header=headers.get("X-Amzn-Oidc-Accesstoken")
            or headers.get("x-amzn-oidc-accesstoken"),
            region=self.region,
            verify_tokens=True,
        )

    def _is_authorized(self, user: User) -> bool:
        """Check if user passes authentication and authorization."""
        if not user.is_authenticated:
            return False
        if self.authorizer is not None and not self.authorizer.is_authorized(user):
            return False
        return True

    # ===== STREAMLIT =====
    def streamlit(self) -> User:
        """
        Streamlit authentication check.

        Example:
            import streamlit as st
            from auth_guard import AuthGuard

            guard = AuthGuard(allowed_domains=['company.com'])
            user = guard.streamlit()

            st.write(f"Welcome {user.email}!")
            st.write(f"Groups: {', '.join(user.groups)}")
        """
        import streamlit as st

        try:
            headers = st.context.headers
            user = self._get_user_from_headers(dict(headers))

            if not self._is_authorized(user):
                st.markdown(
                    f'<meta http-equiv="refresh" content="0; url={self.redirect_url}">',
                    unsafe_allow_html=True,
                )
                st.warning("🔒 Access denied.")
                st.stop()

            return user

        except Exception as e:
            st.markdown(
                f'<meta http-equiv="refresh" content="0; url={self.redirect_url}">',
                unsafe_allow_html=True,
            )
            st.warning("🔒 Authentication failed.")
            st.stop()

    # ===== DASH =====
    def dash(self, func: Callable) -> Callable:
        """
        Dash decorator for protecting apps or callbacks.

        Example:
            from dash import Dash, html, dcc, callback, Output, Input
            from auth_guard import AuthGuard

            guard = AuthGuard(allowed_domains=['company.com'])

            @guard.dash
            def create_app():
                app = Dash(__name__)

                app.layout = html.Div([
                    html.H1("Welcome"),
                    html.Div(id='user-info')
                ])

                @app.callback(Output('user-info', 'children'), Input('user-info', 'id'))
                def show_user(_):
                    user = guard.get_current_user_dash()
                    return f"Logged in as: {user.email}"

                return app

            app = create_app()
            server = app.server
        """
        from flask import redirect, request

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)

                if not self._is_authorized(user):
                    return redirect(self.redirect_url)

                return func(*args, **kwargs)

            except Exception:
                return redirect(self.redirect_url)

        return wrapper

    def get_current_user_dash(self) -> Optional[User]:
        """Get current user in Dash callback."""
        from flask import request

        try:
            headers = dict(request.headers)
            user = self._get_user_from_headers(headers)
            return user if user.is_authenticated else None
        except Exception:
            return None

    # ===== FASTAPI =====
    def fastapi(self):
        """
        FastAPI dependency for protecting routes.

        Example:
            from fastapi import FastAPI, Depends
            from auth_guard import AuthGuard

            app = FastAPI()
            guard = AuthGuard(allowed_domains=['company.com'])

            @app.get("/")
            def home(user = Depends(guard.fastapi())):
                return {
                    "message": f"Hello {user.email}!",
                    "groups": user.groups,
                    "username": user.username
                }

            @app.get("/profile")
            def profile(user = Depends(guard.fastapi())):
                return {
                    "email": user.email,
                    "sub": user.sub,
                    "groups": user.groups
                }
        """
        from fastapi import HTTPException, Request

        def auth_dependency(request: Request) -> User:
            try:
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)

                if not self._is_authorized(user):
                    raise HTTPException(status_code=403, detail="Not authorized")

                return user

            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=401, detail="Authentication failed")

        return auth_dependency

    # ===== GRADIO =====
    def get_current_user_gradio(self, request) -> Optional[User]:
        """
        Get current user in Gradio function.

        Example:
            import gradio as gr
            from auth_guard import AuthGuard

            guard = AuthGuard(allowed_domains=['company.com'])

            def process(text, request: gr.Request):
                user = guard.get_current_user_gradio(request)
                if not user:
                    return "Not authenticated"
                return f"Hello {user.email}! You said: {text}\\n\\nGroups: {', '.join(user.groups) if user.groups else 'None'}"

            with gr.Blocks() as demo:
                gr.Markdown("# Protected App")

                text_input = gr.Textbox(label="Enter text")
                output = gr.Textbox(label="Response")
                submit = gr.Button("Submit")

                submit.click(process, inputs=[text_input], outputs=output)

            demo.launch()
        """
        try:
            if hasattr(request, "headers"):
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)
                return user if self._is_authorized(user) else None
        except Exception:
            return None

    def gradio_middleware(self):
        """
        Middleware for FastAPI+Gradio apps.

        Example:
            import gradio as gr
            from fastapi import FastAPI
            from auth_guard import AuthGuard

            app = FastAPI()
            guard = AuthGuard(allowed_domains=['company.com'])

            @app.middleware("http")
            async def auth_middleware(request, call_next):
                return await guard.gradio_middleware()(request, call_next)

            def greet(name, request: gr.Request):
                user = guard.get_current_user_gradio(request)
                return f"Hello {name}! Logged in as {user.email}"

            demo = gr.Interface(fn=greet, inputs="text", outputs="text")
            app = gr.mount_gradio_app(app, demo, path="/")
        """
        from fastapi import Request
        from fastapi.responses import RedirectResponse

        async def middleware(request: Request, call_next):
            try:
                headers = dict(request.headers)
                user = self._get_user_from_headers(headers)

                if not self._is_authorized(user):
                    return RedirectResponse(url=self.redirect_url)

                request.state.user = user
                return await call_next(request)

            except Exception:
                return RedirectResponse(url=self.redirect_url)

        return middleware

"""
FastAPI authentication module.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ._base_auth import BaseAuth
from .user import User


class FastAPIAuth(BaseAuth):
    """
    Authentication for FastAPI apps.

    RECOMMENDED: Use protect_app() to protect your entire application with one line.

    Example (RECOMMENDED - protect entire app):
        from fastapi import FastAPI, Depends
        from cognito_auth.fastapi import FastAPIAuth

        app = FastAPI()
        auth = FastAPIAuth()
        auth.protect_app(app)  # Protects entire app!

        @app.get("/")
        def index(user: User = Depends(auth.get_auth_user)):
            return {"message": f"Welcome {user.email}!"}

    Example (Alternative - protect specific routes):
        from fastapi import FastAPI, Depends
        from cognito_auth.fastapi import FastAPIAuth

        app = FastAPI()
        auth = FastAPIAuth()

        @app.get("/public")
        def public():
            return {"message": "Public page"}

        @app.get("/protected")
        def protected(user: User = Depends(auth.get_auth_user)):
            return {"message": f"Welcome {user.email}!"}
    """

    def protect_app(self, app: FastAPI) -> None:
        """
        Protect the entire application with authentication.

        This is the RECOMMENDED approach. Call this once after creating your app,
        and all routes will require authentication. Use get_auth_user() dependency
        to access the authenticated user.

        Args:
            app: FastAPI application instance

        Example:
            app = FastAPI()
            auth = FastAPIAuth()
            auth.protect_app(app)  # One line protects everything!

            @app.get("/")
            def index(user: User = Depends(auth.get_auth_user)):
                return {"message": f"Welcome {user.email}!"}
        """

        class AuthMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, auth_instance):
                super().__init__(app)
                self.auth = auth_instance

            async def dispatch(self, request: Request, call_next):
                """Validate authentication before every request."""
                try:
                    headers = dict(request.headers)
                    user = self.auth._get_user_from_headers(headers)

                    if not self.auth._is_authorized(user):
                        return RedirectResponse(url=self.auth.redirect_url)

                    # Store user in request state (FastAPI's equivalent of Flask's g)
                    request.state.user = user

                    return await call_next(request)

                except Exception:
                    return RedirectResponse(url=self.auth.redirect_url)

        app.add_middleware(AuthMiddleware, auth_instance=self)

    def get_auth_user(self, request: Request) -> User:
        """
        Get the authenticated and authorized user for this request.

        This method is designed to be used with FastAPI's Depends() for
        dependency injection.

        When using protect_app() (RECOMMENDED), this retrieves the user that was
        validated by the middleware.

        When not using protect_app(), this validates the user on-demand.

        Args:
            request: FastAPI Request object (automatically injected by Depends)

        Returns:
            Authenticated and authorized User

        Raises:
            HTTPException: 401 if authentication fails, 403 if unauthorized

        Example:
            auth.protect_app(app)

            @app.get("/protected")
            def protected_route(user: User = Depends(auth.get_auth_user)):
                return {"email": user.email}
        """
        # If protect_app() was used, user is stored in request.state
        if hasattr(request.state, "user"):
            return request.state.user

        # Otherwise, validate on-demand (for route-specific protection)
        try:
            headers = dict(request.headers)
            user = self._get_user_from_headers(headers)

            if not self._is_authorized(user):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied. You don't have permission.",
                )

            return user

        except HTTPException:
            # Re-raise HTTPException as-is
            raise
        except Exception as e:
            raise HTTPException(
                status_code=401,
                detail="Authentication failed. Unable to verify your identity.",
            ) from e

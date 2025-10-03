"""
Simple authentication and authorization helper for FastAPI/Gradio apps.
"""

from functools import wraps
from typing import Callable, Optional

from cognito_authorizer import Authorizer
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

from cognito_user import User


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
    FastAPI/Gradio authentication and authorization dependency.

    Use this as a FastAPI dependency to protect routes or entire apps.

    Args:
        redirect_url: Where to redirect on auth failure
        allowed_domains: List of allowed email domains (e.g., ['company.com'])
        allowed_groups: List of allowed Cognito groups (e.g., ['admins'])
        allowed_users: List of allowed usernames or subs
        authorizer: Pre-configured Authorizer instance (overrides other auth params)
        region: AWS region
        require_all: If True, ALL rules must pass. If False, ANY rule can pass.

    Returns:
        User object if authenticated and authorized

    Examples:
        # Example 1: FastAPI with protected routes
        from fastapi import FastAPI, Depends
        from fastapi_gradio_auth import require_auth, get_auth_dependency

        app = FastAPI()
        auth = get_auth_dependency(allowed_domains=['company.com'])

        @app.get("/")
        def read_root(user: User = Depends(auth)):
            return {"message": f"Hello {user.email}!"}

        @app.get("/admin")
        def admin_page(user: User = Depends(get_auth_dependency(allowed_groups=['admins']))):
            return {"message": f"Admin access for {user.username}"}


        # Example 2: Gradio with FastAPI
        import gradio as gr
        from fastapi import FastAPI, Depends

        app = FastAPI()
        auth = get_auth_dependency(allowed_domains=['company.com'])

        def greet(name, request: gr.Request):
            # Access user from request
            user = request.headers.get("user")  # Set by middleware
            return f"Hello {name}! You are logged in as {user}"

        demo = gr.Interface(fn=greet, inputs="text", outputs="text")

        # Add auth middleware
        @app.middleware("http")
        async def auth_middleware(request: Request, call_next):
            try:
                user = await get_user_from_request(request)
                if user and user.is_authenticated:
                    # Check authorization
                    auth_check = get_auth_dependency(allowed_domains=['company.com'])
                    auth_check(request)
                    # Store user in request state
                    request.state.user = user
                    response = await call_next(request)
                    return response
                else:
                    return RedirectResponse(url="https://gds-idea.click/401.html")
            except Exception:
                return RedirectResponse(url="https://gds-idea.click/401.html")

        app = gr.mount_gradio_app(app, demo, path="/")


        # Example 3: Simple Gradio with user display
        import gradio as gr

        def create_gradio_app():
            def process_input(text, request: gr.Request):
                # Get user from Cognito headers
                user = get_current_user(request)
                if user:
                    return f"Hello {user.email}! You said: {text}\\n\\nYour groups: {', '.join(user.groups) if user.groups else 'None'}"
                return "Not authenticated"

            with gr.Blocks() as demo:
                gr.Markdown("# Protected Gradio App")

                with gr.Row():
                    user_info = gr.Markdown("Loading user info...")

                text_input = gr.Textbox(label="Enter something")
                output = gr.Textbox(label="Response")
                submit_btn = gr.Button("Submit")

                submit_btn.click(process_input, inputs=[text_input], outputs=output)

                # Display user info on load
                demo.load(
                    lambda request: f"**Logged in as:** {get_current_user(request).email}\\n**Groups:** {', '.join(get_current_user(request).groups) if get_current_user(request).groups else 'None'}",
                    inputs=None,
                    outputs=user_info
                )

            return demo
    """
    # Build authorizer if not provided
    if authorizer is None and any([allowed_domains, allowed_groups, allowed_users]):
        authorizer = Authorizer.from_lists(
            allowed_domains=allowed_domains,
            allowed_groups=allowed_groups,
            allowed_users=allowed_users,
            require_all=require_all,
        )

    def auth_dependency(request: Request) -> User:
        try:
            # Get Cognito headers from FastAPI request
            headers = request.headers
            user = User(
                oidc_data_header=headers.get("x-amzn-oidc-data"),
                access_token_header=headers.get("x-amzn-oidc-accesstoken"),
                region=region,
                verify_tokens=True,
            )

            # Check authentication
            if not user.is_authenticated:
                raise HTTPException(status_code=401, detail="Not authenticated")

            # Check authorization if authorizer exists
            if authorizer is not None and not authorizer.is_authorized(user):
                raise HTTPException(status_code=403, detail="Not authorized")

            return user

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=401, detail="Authentication failed")

    return auth_dependency


def get_auth_dependency(
    allowed_domains: Optional[list[str]] = None,
    allowed_groups: Optional[list[str]] = None,
    allowed_users: Optional[list[str]] = None,
    authorizer: Optional[Authorizer] = None,
    region: str = "eu-west-2",
    require_all: bool = False,
):
    """
    Helper to create an auth dependency for FastAPI.

    Returns a dependency function that can be used with Depends().
    """
    return require_auth(
        allowed_domains=allowed_domains,
        allowed_groups=allowed_groups,
        allowed_users=allowed_users,
        authorizer=authorizer,
        region=region,
        require_all=require_all,
    )


def get_current_user(request: Request, region: str = "eu-west-2") -> Optional[User]:
    """
    Get the current authenticated user from request headers.
    Works with both FastAPI Request and Gradio Request objects.

    Args:
        request: FastAPI or Gradio Request object
        region: AWS region

    Returns:
        User object if authenticated, None otherwise

    Example:
        # In Gradio function
        def my_function(text, request: gr.Request):
            user = get_current_user(request)
            if user:
                return f"Hello {user.email}!"
            return "Not authenticated"
    """
    try:
        # Handle both FastAPI and Gradio request objects
        if hasattr(request, "headers"):
            headers = request.headers
        else:
            return None

        user = User(
            oidc_data_header=headers.get("x-amzn-oidc-data"),
            access_token_header=headers.get("x-amzn-oidc-accesstoken"),
            region=region,
            verify_tokens=True,
        )
        return user if user.is_authenticated else None
    except Exception:
        return None


async def get_user_from_request(
    request: Request, region: str = "eu-west-2"
) -> Optional[User]:
    """
    Async version of get_current_user for FastAPI middleware.

    Args:
        request: FastAPI Request object
        region: AWS region

    Returns:
        User object if authenticated, None otherwise
    """
    return get_current_user(request, region)

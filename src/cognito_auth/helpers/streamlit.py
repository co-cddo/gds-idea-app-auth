import streamlit as st

from cognito_auth import User

from ..authorizer import Authorizer, EmailRule, GroupRule


def require_auth(
    redirect_url: str = "https://gds-idea.click/401.html",
    allowed_groups: list[str] | None = None,
    allowed_emails: list[str] | None = None,
    require_all: bool | None = False,
    region: str = "eu-west-2",
) -> User:
    """
    Streamlit authentication and authorization check.

    Call this at the start of your app. If authentication/authorization fails,
    user is redirected. Otherwise, returns the authenticated User object.

    Args:
        redirect_url: Where to redirect on auth failure
        allowed_groups: List of allowed Cognito groups (e.g., ['admins'])
        allowed_emails: List of allowed email addresses
        require_all: If True, ALL rules must pass. If False, ANY rule passes.
        region: AWS region

    Returns:
        User object if authenticated and authorized

    Example:
        user = require_auth(allowed_groups=['analysts', 'developers'])
        st.write(f"Hello {user.email}!")
    """

    def redirect(url):
        st.markdown(
            f'<meta http-equiv="refresh" content="0; url={url}">',
            unsafe_allow_html=True,
        )

    try:
        # Get headers and create user
        headers = st.context.headers
        user = User(
            oidc_data_header=headers.get("X-Amzn-Oidc-Data"),
            access_token_header=headers.get("X-Amzn-Oidc-Accesstoken"),
            region=region,
            verify_tokens=True,
        )

        if not user.is_authenticated:
            st.warning("🔒 You are not authenticated.")
            redirect(redirect_url)
            st.stop()

        # Build authorization rules
        rules = []

        # Use provided lists
        if allowed_groups:
            rules.append(GroupRule(set(allowed_groups)))
        if allowed_emails:
            rules.append(EmailRule(set(allowed_emails)))

        # If rules exist, check authorization
        if rules:
            authorizer = Authorizer(rules, require_all=require_all)
            if not authorizer.is_authorized(user):
                st.warning(f"🔒 Access denied for {user.email}")
                redirect(redirect_url)
                st.stop()

        return user

    except Exception:
        st.warning("🔒 Authorization failed. Please log in.")
        redirect(redirect_url)
        st.stop()

from typing import Optional

import streamlit as st

from cognito_user import User

from ..authorizer import Authorizer, DomainRule, EmailRule, GroupRule


def require_auth(
    redirect_url: str = "https://gds-idea.click/401.html",
    allowed_domains: Optional[list[str]] = None,
    allowed_groups: Optional[list[str]] = None,
    allowed_emails: Optional[list[str]] = None,
    require_all: Optional[bool] = False,
    region: str = "eu-west-2",
) -> User:
    """
    Streamlit authentication and authorization check.

    Call this at the start of your app. If authentication/authorization fails,
    user is redirected. Otherwise, returns the authenticated User object.

    Args:
        redirect_url: Where to redirect on auth failure
        allowed_domains: List of allowed email domains (e.g., ['company.com'])
        allowed_groups: List of allowed Cognito groups (e.g., ['admins'])
        allowed_emails: List of allowed emails
        require_all: Pass one rule or all rule?
        region: AWS region

    Returns:
        User object if authenticated and authorized

    Example:
        user = require_auth(allowed_domains=['company.com'], allowed_groups=['analysts'])
        st.write(f"Hello {user.username}!")
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
        if allowed_domains:
            rules.append(DomainRule(set(allowed_domains)))
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

    except Exception as e:
        st.warning("🔒 Authorization failed. Please log in.")
        redirect(redirect_url)
        st.stop()

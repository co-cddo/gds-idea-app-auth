"""
Streamlit authentication module.
"""

import logging
import time

import streamlit as st

from ._base_auth import BaseAuth
from .exceptions import ExpiredTokenError, MissingTokenError
from .user import User

logger = logging.getLogger(__name__)


class StreamlitAuth(BaseAuth):
    """
    Authentication for Streamlit apps.

    Example:
        import streamlit as st
        from cognito_auth.streamlit import StreamlitAuth

        # Auto-loads from environment variables
        auth = StreamlitAuth()
        user = auth.get_auth_user()

        st.write(f"Welcome {user.email}!")
        st.write(f"Groups: {', '.join(user.groups)}")
    """

    def get_auth_user(self) -> User:
        """
        Get the authenticated and authorised user for this request.

        Validates user from Cognito headers and checks authorisation.
        Stops execution with error message if authentication or authorisation fails.

        Note: Unlike other frameworks, Streamlit has no native redirect function.
        This method displays an error message and stops execution using st.stop(),
        which prevents any code after this call from running.

        Returns:
            Authenticated and authorised User

        Example:
            auth = StreamlitAuth()
            user = auth.get_auth_user()
            st.write(f"Hello {user.email}")
        """
        try:
            # Try headers first (ALB might have refreshed tokens)
            headers = st.context.headers
            logger.debug(
                f"Attempting authentication from headers "
                f"(available keys: {list(dict(headers).keys())})"
            )
            user = self._get_user_from_headers(dict(headers))
            return self._authorize_and_cache_user(user)

        except MissingTokenError as e:
            # Headers missing - likely WebSocket reconnection, try cache
            return self._get_cached_user_or_fail(e)

        except ExpiredTokenError as e:
            self._handle_expired_token(e)

        except Exception as e:
            self._handle_auth_error(e)

    def _authorize_and_cache_user(self, user: User) -> User:
        """Check authorization and cache user in session state."""
        if not self._is_authorised(user):
            logger.warning(
                f"User not authorized: email={user.email} groups={user.groups}"
            )
            st.error(
                "🔒 Access denied. You don't have permission to access "
                "this application."
            )
            st.info(
                "Please contact your administrator if you believe this is an error."
            )
            st.stop()

        # Cache user in session state
        st.session_state["_cognito_auth_user"] = user
        logger.info(
            f"User authenticated: email={user.email} groups={user.groups} "
            f"exp={user.exp}"
        )
        return user

    def _get_cached_user_or_fail(self, error: MissingTokenError) -> User:
        """Get cached user if available, otherwise fail with error."""
        cached_user = st.session_state.get("_cognito_auth_user")

        if not cached_user:
            logger.error(
                f"Authentication failed - missing headers and no cache: {error}"
            )
            st.error("🔒 Session initialization failed. Please refresh the page.")
            st.stop()

        # Check if cached token has expired
        if cached_user.exp and cached_user.exp.timestamp() < time.time():
            logger.warning(f"Cached token expired at {cached_user.exp}")
            st.session_state.pop("_cognito_auth_user", None)
            st.error(
                "🔒 Your session has expired. Please refresh the page to continue."
            )
            st.info("Sessions expire after 60 minutes for security.")
            st.stop()

        logger.debug(
            f"Headers missing (WebSocket reconnect?) - "
            f"using cached user (expires at {cached_user.exp})"
        )
        return cached_user

    def _handle_expired_token(self, error: ExpiredTokenError) -> None:
        """Handle expired token error."""
        logger.warning(f"Token expired: {error}")
        st.session_state.pop("_cognito_auth_user", None)
        st.error("🔒 Your session has expired. Please refresh the page to continue.")
        st.info("Sessions expire after 60 minutes for security.")
        st.stop()

    def _handle_auth_error(self, error: Exception) -> None:
        """Handle unexpected authentication error."""
        logger.error(
            f"Authentication failed with unexpected error: {error}", exc_info=True
        )
        st.error("🔒 Authentication failed. Please try refreshing the page.")
        st.info("If the problem persists, contact support.")
        st.stop()

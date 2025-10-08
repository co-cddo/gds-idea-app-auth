"""
Streamlit authentication module.
"""

import streamlit as st

from ._base_auth import BaseAuth
from .user import User


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
            headers = st.context.headers
            user = self._get_user_from_headers(dict(headers))

            if not self._is_authorised(user):
                st.error(
                    "🔒 Access denied. You don't have permission to access "
                    "this application."
                )
                st.info(
                    "Please contact your administrator if you believe this "
                    "is an error."
                )
                st.stop()

            return user

        except Exception:
            st.error("🔒 Authentication failed.")
            st.info(
                "Unable to verify your identity. Please try again or "
                "contact support."
            )
            st.stop()

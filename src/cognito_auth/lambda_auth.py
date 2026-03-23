"""
AWS Lambda authentication module.
"""

import logging

from ._base_auth import BaseAuth
from .user import User

logger = logging.getLogger(__name__)


class LambdaAuth(BaseAuth):
    """
    Authentication for AWS Lambda functions behind an ALB.

    Use this when your Lambda function is a target of an Application Load
    Balancer with OIDC (Cognito) authentication configured. The ALB forwards
    OIDC headers in the Lambda event, and this class verifies them.

    Example:
        from cognito_auth.lambda_auth import LambdaAuth
        from cognito_auth import Authoriser

        authoriser = Authoriser.from_lists(allowed_groups=["developers"])
        auth = LambdaAuth(authoriser=authoriser)

        def handler(event, context):
            try:
                user = auth.get_auth_user(event)
            except Exception:
                return {
                    "statusCode": 302,
                    "headers": {"Location": auth.redirect_url},
                    "body": "",
                }

            return {
                "statusCode": 200,
                "body": f"Hello {user.email}!",
            }
    """

    def get_auth_user(self, event: dict) -> User:
        """
        Get the authenticated and authorised user from an ALB Lambda event.

        Extracts OIDC headers from the event, verifies the tokens, and checks
        authorisation rules.

        Args:
            event: ALB Lambda event dictionary. Must contain a "headers" key
                with the ALB OIDC headers (x-amzn-oidc-data and
                x-amzn-oidc-accesstoken).

        Returns:
            Authenticated and authorised User

        Raises:
            MissingTokenError: If required OIDC headers are not present
            InvalidTokenError: If token verification fails
            ExpiredTokenError: If tokens have expired
            PermissionError: If user is authenticated but not authorised

        Example:
            auth = LambdaAuth()

            def handler(event, context):
                try:
                    user = auth.get_auth_user(event)
                except Exception:
                    return {
                        "statusCode": 302,
                        "headers": {"Location": auth.redirect_url},
                        "body": "",
                    }

                return {
                    "statusCode": 200,
                    "body": f"Hello {user.email}!",
                }
        """
        headers = event.get("headers", {})
        user = self._get_user_from_headers(headers)

        if not self._is_authorised(user):
            logger.warning(
                "User not authorised: email=%s, groups=%s",
                user.email,
                user.groups,
            )
            raise PermissionError(
                "Access denied. You don't have permission to access this resource."
            )

        return user

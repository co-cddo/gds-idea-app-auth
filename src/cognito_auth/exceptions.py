class AuthenticationError(Exception):
    """Base exception for authentication errors"""

    pass


class InvalidTokenError(AuthenticationError):
    """Raised when token is invalid or verification fails"""

    pass


class ExpiredTokenError(AuthenticationError):
    """Raised when token has expired"""

    pass


class MissingTokenError(AuthenticationError):
    """Raised when required token headers are missing"""

    pass

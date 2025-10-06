from typing import Protocol

from .user import User


class AuthorizationRule(Protocol):
    """Protocol for authorization rules"""

    def is_allowed(self, user: User) -> bool:
        """Check if user meets this rule"""
        ...


class GroupRule:
    """Allow users in specific Cognito groups"""

    def __init__(self, allowed_groups: set[str]):
        self.allowed_groups = allowed_groups

    def is_allowed(self, user: User) -> bool:
        user_groups = set(user.access_claims.get("cognito:groups", []))
        return bool(user_groups & self.allowed_groups)


class EmailRule:
    """Allow specific users by email address"""

    def __init__(self, allowed_emails: set[str]):
        self.allowed_emails = allowed_emails

    def is_allowed(self, user: User) -> bool:
        return user.email in self.allowed_emails


class Authorizer:
    """Handles authorization logic using composable rules"""

    def __init__(self, rules: list[AuthorizationRule], require_all: bool = False):
        """
        Args:
            rules: List of authorization rules
            require_all: If True, ALL rules must pass. If False, ANY rule can pass.
        """
        self.rules = rules
        self.require_all = require_all

    def is_authorized(self, user: User) -> bool:
        """Check if user is authorized"""
        if not user.is_authenticated:
            return False

        if not self.rules:
            return True  # No rules = allow all authenticated users

        results = [rule.is_allowed(user) for rule in self.rules]

        if self.require_all:
            return all(results)
        else:
            return any(results)

    @classmethod
    def from_lists(
        cls,
        allowed_groups: list[str] | None = None,
        allowed_users: list[str] | None = None,
        require_all: bool = False,
    ) -> "Authorizer":
        """
        Create an Authorizer from simple lists of allowed values.

        Args:
            allowed_groups: List of allowed Cognito groups
            allowed_users: List of allowed email addresses
            require_all: If True, ALL rules must pass. If False, ANY rule passes.

        Returns:
            Authorizer instance with the specified rules
        """
        rules: list[AuthorizationRule] = []

        if allowed_groups:
            rules.append(GroupRule(set(allowed_groups)))

        if allowed_users:
            rules.append(EmailRule(set(allowed_users)))

        return cls(rules, require_all=require_all)

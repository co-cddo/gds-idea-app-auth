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


class DomainRule:
    """Allow users with specific email domains"""

    def __init__(self, allowed_domains: set[str]):
        self.allowed_domains = allowed_domains

    def is_allowed(self, user: User) -> bool:
        print(f"Checking {user.email_domain} in {self.allowed_domains}")
        return user.email_domain in self.allowed_domains


class EmailRule:
    """Allow specific users by username or sub"""

    def __init__(self, allowed_emails: set[str]):
        self.allowed_emails = allowed_emails

    def is_allowed(self, user: User) -> bool:
        print(f"Checking {user.email} in {self.allowed_emails}")
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
            print(f"{user.name} is not authenticated")
            return False

        if not self.rules:
            return True  # No rules = allow all authenticated users

        results = [rule.is_allowed(user) for rule in self.rules]

        if self.require_all:
            return all(results)
        else:
            return any(results)

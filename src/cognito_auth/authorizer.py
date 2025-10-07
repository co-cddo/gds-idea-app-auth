import json
import os
from pathlib import Path
from typing import Any, Protocol

from cachetools import TTLCache, cached
from pydantic import (
    BaseModel,
    EmailStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .user import User

# TTL cache for config loading - 5 minutes
_config_cache = TTLCache(maxsize=1, ttl=300)


class AuthConfig(BaseModel):
    """Configuration for authorization rules."""

    allowed_groups: list[str] | None = None
    allowed_users: list[str] | None = None
    require_all: bool = False

    @field_validator("allowed_users")
    @classmethod
    def validate_emails(cls, v):
        """Validate that all users are valid email addresses."""
        if v is None:
            return None

        # Validate each email with Pydantic's EmailStr
        for email in v:
            try:
                EmailStr._validate(email)
            except ValidationError as e:
                raise ValueError(
                    f"Invalid email address '{email}': must be a valid email format"
                ) from e

        return v  # Already strings

    @model_validator(mode="after")
    def check_at_least_one_rule(self):
        """Ensure at least one authorization rule is specified."""
        if not self.allowed_groups and not self.allowed_users:
            raise ValueError(
                "Config must specify at least one of: allowed_groups, allowed_users"
            )
        return self


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

    @classmethod
    @cached(cache=_config_cache)
    def from_config(cls) -> "Authorizer":
        """
        Create an Authorizer from configuration with automatic TTL caching.

        Config is cached for 5 minutes to allow adding new users without restarting.
        Call clear_config_cache() to force immediate reload.

        Requires one of these environment variables:
        - COGNITO_AUTH_CONFIG_PATH: Path to local JSON file (development)
        - COGNITO_AUTH_SECRET_NAME: AWS Secrets Manager secret name (production)

        Config format (JSON):
        {
            "allowed_groups": ["developers", "admins"],
            "allowed_users": ["user@example.com"],
            "require_all": false
        }

        Returns:
            Authorizer instance configured from the loaded settings

        Raises:
            ValueError: If neither environment variable is set or config is invalid

        Example:
            # Development
            export COGNITO_AUTH_CONFIG_PATH=./auth-config.json
            authorizer = Authorizer.from_config()

            # Production
            export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
            authorizer = Authorizer.from_config()
        """
        config_path = os.getenv("COGNITO_AUTH_CONFIG_PATH")
        secret_name = os.getenv("COGNITO_AUTH_SECRET_NAME")

        if config_path:
            # Development: load from local file
            raw_config = cls._load_from_file(config_path)
        elif secret_name:
            # Production: load from AWS Secrets Manager
            raw_config = cls._load_from_aws_secrets(secret_name)
        else:
            raise ValueError(
                "Must set either COGNITO_AUTH_CONFIG_PATH (for local file) "
                "or COGNITO_AUTH_SECRET_NAME (for AWS Secrets Manager)"
            )

        # Parse and validate with pydantic
        config = AuthConfig.model_validate(raw_config)

        return cls.from_lists(
            allowed_groups=config.allowed_groups,
            allowed_users=config.allowed_users,
            require_all=config.require_all,
        )

    @staticmethod
    def _load_from_file(file_path: str) -> dict[str, Any]:
        """Load configuration from a local JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")

        try:
            with path.open() as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file {file_path}: {e}") from e

    @staticmethod
    def _load_from_aws_secrets(secret_name: str) -> dict[str, Any]:
        """Load configuration from AWS Secrets Manager."""
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "boto3 is required for AWS Secrets Manager. "
                "Install with: pip install boto3"
            ) from e

        try:
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_name)
            return json.loads(response["SecretString"])
        except Exception as e:
            raise RuntimeError(
                f"Failed to load config from AWS Secrets Manager "
                f"(secret: {secret_name}): {e}"
            ) from e

    @classmethod
    def clear_config_cache(cls) -> None:
        """
        Manually clear the config cache to force immediate reload.

        Useful when you need to apply config changes immediately without
        waiting for the 5-minute TTL to expire.

        Example:
            from cognito_auth import Authorizer

            # After updating secret in AWS
            Authorizer.clear_config_cache()

            # Next call will fetch fresh config
            guard = AuthGuard.from_config()
        """
        _config_cache.clear()

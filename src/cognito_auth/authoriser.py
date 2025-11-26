import json
import logging
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

logger = logging.getLogger(__name__)

# TTL cache for config loading - 5 minutes
_config_cache = TTLCache(maxsize=1, ttl=300)


class AuthConfig(BaseModel):
    """Configuration for authorisation rules."""

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
        """Ensure at least one authorisation rule is specified."""
        if not self.allowed_groups and not self.allowed_users:
            raise ValueError(
                "Config must specify at least one of: allowed_groups, allowed_users"
            )
        return self


class AuthorisationRule(Protocol):
    """Protocol for authorisation rules"""

    def is_allowed(self, user: User) -> bool:
        """Check if user meets this rule"""
        ...


class GroupRule:
    """Allow users in specific Cognito groups"""

    def __init__(self, allowed_groups: set[str]):
        self.allowed_groups = allowed_groups

    def is_allowed(self, user: User) -> bool:
        user_groups = set(user.access_claims.get("cognito:groups", []))
        allowed = bool(user_groups & self.allowed_groups)
        logger.debug(
            "GroupRule check: user_groups=%s, allowed_groups=%s, result=%s",
            user_groups,
            self.allowed_groups,
            allowed,
        )
        return allowed


class EmailRule:
    """Allow specific users by email address"""

    def __init__(self, allowed_emails: set[str]):
        # Normalise emails to lowercase for case-insensitive comparison
        self.allowed_emails = {email.lower() for email in allowed_emails}

    def is_allowed(self, user: User) -> bool:
        allowed = user.email.lower() in self.allowed_emails
        logger.debug("EmailRule check: user_email=%s, allowed=%s", user.email, allowed)
        return allowed


class Authoriser:
    """Handles authorisation logic using composable rules"""

    def __init__(self, rules: list[AuthorisationRule], require_all: bool = False):
        """
        Args:
            rules: List of authorisation rules
            require_all: If True, ALL rules must pass. If False, ANY rule can pass.
        """
        self.rules = rules
        self.require_all = require_all

    def is_authorised(self, user: User) -> bool:
        """Check if user is authorised"""
        logger.debug(
            "Checking authorisation for user: email=%s, groups=%s",
            user.email,
            user.groups,
        )

        if not user.is_authenticated:
            logger.warning("User not authenticated, denying access")
            return False

        if not self.rules:
            logger.debug("No rules configured, allowing all authenticated users")
            return True  # No rules = allow all authenticated users

        results = [rule.is_allowed(user) for rule in self.rules]
        logger.debug(
            "Rule evaluation results: %s (require_all=%s)", results, self.require_all
        )

        if self.require_all:
            authorised = all(results)
        else:
            authorised = any(results)

        if authorised:
            logger.info("User authorised: email=%s, groups=%s", user.email, user.groups)
        else:
            logger.warning(
                "User denied access: email=%s, groups=%s", user.email, user.groups
            )

        return authorised

    @classmethod
    def from_lists(
        cls,
        allowed_groups: list[str] | None = None,
        allowed_users: list[str] | None = None,
        require_all: bool = False,
    ) -> "Authoriser":
        """
        Create an Authoriser from simple lists of allowed values.

        Args:
            allowed_groups: List of allowed Cognito groups
            allowed_users: List of allowed email addresses
            require_all: If True, ALL rules must pass. If False, ANY rule passes.

        Returns:
            Authoriser instance with the specified rules
        """
        rules: list[AuthorisationRule] = []

        if allowed_groups:
            rules.append(GroupRule(set(allowed_groups)))

        if allowed_users:
            rules.append(EmailRule(set(allowed_users)))

        return cls(rules, require_all=require_all)

    @classmethod
    @cached(cache=_config_cache)
    def from_config(cls) -> "Authoriser":
        """
        Create an Authoriser from configuration with automatic TTL caching.

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
            Authoriser instance configured from the loaded settings

        Raises:
            ValueError: If neither environment variable is set or config is invalid

        Example:
            # Development
            export COGNITO_AUTH_CONFIG_PATH=./auth-config.json
            authoriser = Authoriser.from_config()

            # Production
            export COGNITO_AUTH_SECRET_NAME=my-app/auth-config
            authoriser = Authoriser.from_config()
        """
        config_path = os.getenv("COGNITO_AUTH_CONFIG_PATH")
        secret_name = os.getenv("COGNITO_AUTH_SECRET_NAME")

        logger.debug(
            "Loading authoriser config: config_path=%s, secret_name=%s",
            config_path or "not set",
            secret_name or "not set",
        )

        if config_path:
            # Development: load from local file
            logger.info("Loading config from local file: %s", config_path)
            raw_config = cls._load_from_file(config_path)
        elif secret_name:
            # Production: load from AWS Secrets Manager
            logger.info("Loading config from AWS Secrets Manager: %s", secret_name)
            raw_config = cls._load_from_aws_secrets(secret_name)
        else:
            logger.error(
                "No config source specified "
                "(COGNITO_AUTH_CONFIG_PATH or COGNITO_AUTH_SECRET_NAME)"
            )
            raise ValueError(
                "Must set either COGNITO_AUTH_CONFIG_PATH (for local file) "
                "or COGNITO_AUTH_SECRET_NAME (for AWS Secrets Manager)"
            )

        # Parse and validate with pydantic
        logger.debug("Validating config with pydantic")
        config = AuthConfig.model_validate(raw_config)

        logger.info(
            "Authoriser config loaded: allowed_groups=%s, "
            "allowed_users=%s, require_all=%s",
            config.allowed_groups,
            len(config.allowed_users) if config.allowed_users else 0,
            config.require_all,
        )

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
            logger.error("Config file not found: %s", file_path)
            raise FileNotFoundError(f"Config file not found: {file_path}")

        try:
            with path.open() as f:
                config = json.load(f)
                logger.debug("Successfully loaded config from file: %s", file_path)
                return config
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in config file %s: %s", file_path, e)
            raise ValueError(f"Invalid JSON in config file {file_path}: {e}") from e

    @staticmethod
    def _load_from_aws_secrets(secret_name: str) -> dict[str, Any]:
        """Load configuration from AWS Secrets Manager."""
        try:
            import boto3
        except ImportError as e:
            logger.error("boto3 not installed, cannot load from AWS Secrets Manager")
            raise ImportError(
                "boto3 is required for AWS Secrets Manager. "
                "Install with: pip install boto3"
            ) from e

        try:
            logger.debug("Fetching secret from AWS Secrets Manager: %s", secret_name)
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_name)
            config = json.loads(response["SecretString"])
            logger.debug("Successfully loaded config from AWS Secrets Manager")
            return config
        except Exception as e:
            logger.error(
                "Failed to load config from AWS Secrets Manager (secret: %s): %s",
                secret_name,
                e,
            )

            return {
                "allowed_groups": ["gds-idea"],
                "allowed_emails": [],
                "require_all": True,
            }
            # raise RuntimeError(
            #     f"Failed to load config from AWS Secrets Manager "
            #     f"(secret: {secret_name}): {e}"
            # ) from e

    @classmethod
    def clear_config_cache(cls) -> None:
        """
        Manually clear the config cache to force immediate reload.

        Useful when you need to apply config changes immediately without
        waiting for the 5-minute TTL to expire.

        Example:
            from cognito_auth import Authoriser

            # After updating secret in AWS
            Authoriser.clear_config_cache()

            # Next call will fetch fresh config
            guard = AuthGuard.from_config()
        """
        logger.info("Clearing authoriser config cache")
        _config_cache.clear()

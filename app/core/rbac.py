"""
Role-Based Access Control (RBAC) utilities module.

This module provides comprehensive RBAC functionality including:
- Role hierarchy validation
- Permission checking
- Role comparison utilities
- Helper functions for authorization

Author: HRMS Development Team
"""

from typing import List, Set

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class RBACManager:
    """
    Manager class for Role-Based Access Control operations.
    Provides methods to check roles, permissions, and hierarchy.
    """

    @staticmethod
    def get_role_level(role: str) -> int:
        """
        Get the hierarchy level of a role.

        Args:
            role: Role name

        Returns:
            Integer representing role level (higher = more privileges)
            Returns 0 if role is invalid
        """
        return settings.ROLE_HIERARCHY.get(role, 0)

    @staticmethod
    def is_valid_role(role: str) -> bool:
        """
        Check if a role is valid in the system.

        Args:
            role: Role name to validate

        Returns:
            True if role is valid, False otherwise
        """
        return role in settings.ROLES or role == "admin"

    @staticmethod
    def has_higher_or_equal_role(user_role: str, required_role: str) -> bool:
        """
        Check if user's role is higher than or equal to required role.

        Args:
            user_role: User's current role
            required_role: Minimum required role

        Returns:
            True if user has sufficient role level, False otherwise
        """
        user_level = RBACManager.get_role_level(user_role)
        required_level = RBACManager.get_role_level(required_role)

        return user_level >= required_level

    @staticmethod
    def get_role_permissions(role: str) -> List[str]:
        """
        Get all permissions associated with a role.

        Args:
            role: Role name

        Returns:
            List of permission strings for the role
        """
        # Handle admin alias
        if role == "admin":
            role = "HR_Admin"

        return settings.ROLE_PERMISSIONS.get(role, [])

    @staticmethod
    def get_all_permissions(roles: List[str]) -> Set[str]:
        """
        Get all unique permissions from multiple roles.

        Args:
            roles: List of role names

        Returns:
            Set of all unique permissions
        """
        all_permissions = set()
        for role in roles:
            all_permissions.update(RBACManager.get_role_permissions(role))

        return all_permissions

    @staticmethod
    def has_permission(user_roles: List[str], required_permission: str) -> bool:
        """
        Check if user has a specific permission based on their roles.

        Args:
            user_roles: List of user's roles
            required_permission: Permission to check

        Returns:
            True if user has the permission, False otherwise
        """
        all_permissions = RBACManager.get_all_permissions(user_roles)
        return required_permission in all_permissions

    @staticmethod
    def has_any_permission(
        user_roles: List[str], required_permissions: List[str]
    ) -> bool:
        """
        Check if user has any of the specified permissions.

        Args:
            user_roles: List of user's roles
            required_permissions: List of permissions to check

        Returns:
            True if user has at least one permission, False otherwise
        """
        all_permissions = RBACManager.get_all_permissions(user_roles)
        return any(perm in all_permissions for perm in required_permissions)

    @staticmethod
    def has_all_permissions(
        user_roles: List[str], required_permissions: List[str]
    ) -> bool:
        """
        Check if user has all of the specified permissions.

        Args:
            user_roles: List of user's roles
            required_permissions: List of permissions to check

        Returns:
            True if user has all permissions, False otherwise
        """
        all_permissions = RBACManager.get_all_permissions(user_roles)
        return all(perm in all_permissions for perm in required_permissions)

    @staticmethod
    def can_manage_role(user_role: str, target_role: str) -> bool:
        """
        Check if a user can manage (assign/revoke) a target role.
        Users can only manage roles lower than their own.

        Args:
            user_role: Role of the user performing the action
            target_role: Role to be managed

        Returns:
            True if user can manage the target role, False otherwise
        """
        user_level = RBACManager.get_role_level(user_role)
        target_level = RBACManager.get_role_level(target_role)

        # User must have higher role level to manage target role
        return user_level > target_level

    @staticmethod
    def get_manageable_roles(user_role: str) -> List[str]:
        """
        Get list of roles that a user can manage.

        Args:
            user_role: User's current role

        Returns:
            List of role names that can be managed
        """
        user_level = RBACManager.get_role_level(user_role)

        manageable = []
        for role, level in settings.ROLE_HIERARCHY.items():
            if level < user_level and role in settings.ROLES:
                manageable.append(role)

        return sorted(
            manageable, key=lambda r: settings.ROLE_HIERARCHY[r], reverse=True
        )

    @staticmethod
    def get_asgardeo_group(role: str) -> str:
        """
        Get the Asgardeo group name for a role.

        Args:
            role: Role name

        Returns:
            Asgardeo group name
        """
        return settings.ASGARDEO_GROUP_MAPPING.get(role, "Employees")

    @staticmethod
    def get_role_hierarchy() -> dict:
        """
        Get the complete role hierarchy.

        Returns:
            Dictionary mapping roles to their hierarchy levels
        """
        return settings.ROLE_HIERARCHY.copy()

    @staticmethod
    def get_role_info(role: str) -> dict:
        """
        Get comprehensive information about a role.

        Args:
            role: Role name

        Returns:
            Dictionary with role information including level, permissions, and group
        """
        return {
            "role": role,
            "level": RBACManager.get_role_level(role),
            "permissions": RBACManager.get_role_permissions(role),
            "asgardeo_group": RBACManager.get_asgardeo_group(role),
            "is_valid": RBACManager.is_valid_role(role),
        }

    @staticmethod
    def validate_role_transition(
        current_role: str, new_role: str, actor_role: str
    ) -> tuple[bool, str]:
        """
        Validate if a role transition is allowed.

        Args:
            current_role: User's current role
            new_role: Target role
            actor_role: Role of the person making the change

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if new role is valid
        if not RBACManager.is_valid_role(new_role):
            return (
                False,
                f"Invalid role: {new_role}. Must be one of: {', '.join(settings.ROLES)}",
            )

        # Check if actor can manage the target role
        if not RBACManager.can_manage_role(actor_role, new_role):
            return False, f"Insufficient privileges to assign role: {new_role}"

        # Check if actor can manage the current role (for role changes)
        if current_role != new_role and not RBACManager.can_manage_role(
            actor_role, current_role
        ):
            return (
                False,
                f"Insufficient privileges to change user from role: {current_role}",
            )

        return True, ""

    @staticmethod
    def log_authorization_check(
        user_id: str, user_roles: List[str], required_resource: str, allowed: bool
    ):
        """
        Log authorization check for audit purposes.

        Args:
            user_id: User identifier
            user_roles: User's roles
            required_resource: Resource or permission being checked
            allowed: Whether access was granted
        """
        status = "GRANTED" if allowed else "DENIED"
        logger.info(
            f"Authorization {status}: user={user_id}, "
            f"roles={','.join(user_roles)}, "
            f"resource={required_resource}"
        )


# Convenience functions for common RBAC checks
def is_admin(roles: List[str]) -> bool:
    """Check if user has admin (HR_Admin) role."""
    return "HR_Admin" in roles or "admin" in roles


def is_hr_manager_or_above(roles: List[str]) -> bool:
    """Check if user has HR_Manager role or higher."""
    for role in roles:
        if RBACManager.get_role_level(role) >= RBACManager.get_role_level("HR_Manager"):
            return True
    return False


def is_manager_or_above(roles: List[str]) -> bool:
    """Check if user has manager role or higher."""
    for role in roles:
        if RBACManager.get_role_level(role) >= RBACManager.get_role_level("manager"):
            return True
    return False


def get_highest_role(roles: List[str]) -> str:
    """
    Get the highest role from a list of roles.

    Args:
        roles: List of role names

    Returns:
        The role with the highest hierarchy level
    """
    if not roles:
        return settings.DEFAULT_ROLE

    return max(roles, key=lambda r: RBACManager.get_role_level(r))


def normalize_role(role: str) -> str:
    """
    Normalize role name (handle aliases).

    Args:
        role: Role name

    Returns:
        Normalized role name
    """
    if role == "admin":
        return "HR_Admin"
    return role

"""
Asgardeo client initialization for User Management Service.

This module provides a singleton instance of the AsgardeoClient
configured with credentials from environment variables.
"""

from typing import Any, Dict, List, Optional

from app.asgardeo.asgardeo import AsgardeoClient, AsgardeoConfig
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def create_asgardeo_client() -> AsgardeoClient:
    """
    Create and configure Asgardeo client instance.

    Returns:
        Configured AsgardeoClient instance

    Raises:
        ValueError: If required configuration is missing
    """
    if not settings.ASGARDEO_ORG:
        raise ValueError("ASGARDEO_ORG environment variable is required")
    if not settings.ASGARDEO_CLIENT_ID:
        raise ValueError("ASGARDEO_CLIENT_ID environment variable is required")
    if not settings.ASGARDEO_CLIENT_SECRET:
        raise ValueError("ASGARDEO_CLIENT_SECRET environment variable is required")

    config = AsgardeoConfig(
        organization=settings.ASGARDEO_ORG,
        client_id=settings.ASGARDEO_CLIENT_ID,
        client_secret=settings.ASGARDEO_CLIENT_SECRET,
    )

    logger.info(
        f"Initialized Asgardeo client for organization: {settings.ASGARDEO_ORG}"
    )
    return AsgardeoClient(config)


class AsgardeoService:
    """
    Service layer for Asgardeo user management operations.
    Provides business logic wrapper around AsgardeoClient.
    """

    def __init__(self, client: AsgardeoClient):
        """
        Initialize Asgardeo service.

        Args:
            client: Configured AsgardeoClient instance
        """
        self.client = client

    async def create_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new user in Asgardeo.

        Args:
            email: User email address
            password: User password
            first_name: User first name
            last_name: User last name
            phone: User phone number (optional)

        Returns:
            Dict containing:
                - asgardeo_id: User ID in Asgardeo
                - username: Username in Asgardeo
                - email: User email
                - first_name: User first name
                - last_name: User last name

        Raises:
            Exception: If user creation fails
        """
        # Asgardeo username format: DEFAULT/<email>
        username = f"DEFAULT/{email}"

        try:
            user_data = await self.client.create_user(
                username=username,
                password=password,
                email=email,
                given_name=first_name,
                family_name=last_name,
                verify_email=True,
            )

            asgardeo_id = user_data.get("id")
            logger.info(f"Created user in Asgardeo: {asgardeo_id} ({email})")

            return {
                "asgardeo_id": asgardeo_id,
                "username": user_data.get("userName"),
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
            }

        except Exception as e:
            logger.error(f"Failed to create user in Asgardeo ({email}): {e}")
            raise

    async def update_user(
        self,
        asgardeo_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        phone: Optional[str] = None,
        updates: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Update user information in Asgardeo.

        Args:
            asgardeo_id: User ID in Asgardeo
            first_name: New first name (optional)
            last_name: New last name (optional)
            phone: New phone number (optional)
            updates: Additional SCIM updates (optional)

        Returns:
            Updated user data from Asgardeo

        Raises:
            Exception: If update fails
        """
        try:
            update_data = updates or {}

            # Build name object if name fields provided
            if first_name or last_name:
                update_data.setdefault("name", {})
                if first_name:
                    update_data["name"]["givenName"] = first_name
                if last_name:
                    update_data["name"]["familyName"] = last_name

            # Add phone number if provided
            if phone:
                update_data["phoneNumbers"] = [{"value": phone, "type": "mobile"}]

            result = await self.client.patch_user(asgardeo_id, update_data)
            logger.info(f"Updated user in Asgardeo: {asgardeo_id}")
            return result

        except Exception as e:
            logger.error(f"Failed to update user in Asgardeo ({asgardeo_id}): {e}")
            raise

    async def get_user(self, asgardeo_id: str) -> Dict[str, Any]:
        """
        Get user details from Asgardeo.

        Args:
            asgardeo_id: User ID in Asgardeo

        Returns:
            User data from Asgardeo

        Raises:
            Exception: If user not found or fetch fails
        """
        try:
            return await self.client.get_user(asgardeo_id)
        except Exception as e:
            logger.error(f"Failed to get user from Asgardeo ({asgardeo_id}): {e}")
            raise

    async def list_users(
        self, start_index: int = 1, count: int = 50
    ) -> List[Dict[str, Any]]:
        """
        List users from Asgardeo with pagination.

        Args:
            start_index: Starting index (1-based)
            count: Number of users to retrieve

        Returns:
            List of user data dictionaries

        Raises:
            Exception: If list operation fails
        """
        try:
            result = await self.client.list_users(start_index=start_index, count=count)
            return result.get("Resources", [])
        except Exception as e:
            logger.error(f"Failed to list users from Asgardeo: {e}")
            raise

    async def delete_user(self, asgardeo_id: str) -> None:
        """
        Delete user from Asgardeo.

        Args:
            asgardeo_id: User ID in Asgardeo

        Raises:
            Exception: If deletion fails
        """
        try:
            await self.client.delete_user(asgardeo_id)
            logger.info(f"Deleted user from Asgardeo: {asgardeo_id}")
        except Exception as e:
            logger.error(f"Failed to delete user from Asgardeo ({asgardeo_id}): {e}")
            raise

    async def disable_user(self, asgardeo_id: str) -> None:
        """
        Disable user in Asgardeo by setting active=false.

        Args:
            asgardeo_id: User ID in Asgardeo

        Raises:
            Exception: If disable fails
        """
        try:
            operations = [{"op": "replace", "path": "active", "value": False}]
            await self.client.patch_user(asgardeo_id, operations)
            logger.info(f"Disabled user in Asgardeo: {asgardeo_id}")
        except Exception as e:
            logger.error(f"Failed to disable user in Asgardeo ({asgardeo_id}): {e}")
            raise

    async def enable_user(self, asgardeo_id: str) -> None:
        """
        Enable user in Asgardeo by setting active=true.

        Args:
            asgardeo_id: User ID in Asgardeo

        Raises:
            Exception: If enable fails
        """
        try:
            operations = [{"op": "replace", "path": "active", "value": True}]
            await self.client.patch_user(asgardeo_id, operations)
            logger.info(f"Enabled user in Asgardeo: {asgardeo_id}")
        except Exception as e:
            logger.error(f"Failed to enable user in Asgardeo ({asgardeo_id}): {e}")
            raise

    async def assign_role(self, asgardeo_id: str, role_name: str) -> None:
        """
        Assign role to user via group membership.

        Maps application roles to Asgardeo groups and adds user to the group.

        Args:
            asgardeo_id: User ID in Asgardeo
            role_name: Role name (HR_Admin, HR_Manager, Manager, Employee)

        Raises:
            Exception: If role assignment fails
        """
        try:
            # Map application roles to Asgardeo groups
            # Using underscore format to match actual Asgardeo group names
            role_group_mapping = {
                "HR_Admin": "HR_Administrators",
                "HR_Manager": "HR_Managers",
                "Manager": "Team_Managers",
                "manager": "Team_Managers",
                "Employee": "Employees",
                "employee": "Employees",
            }

            group_name = role_group_mapping.get(role_name)
            if not group_name:
                logger.warning(f"No group mapping found for role: {role_name}")
                return

            # Find group by name
            group = await self.client.find_group_by_name(group_name)
            if not group:
                logger.error(f"Group not found in Asgardeo: {group_name}")
                logger.warning(
                    f"Please create group '{group_name}' in Asgardeo Console"
                )
                return

            # Add user to group
            group_id = group.get("id")
            await self.client.add_user_to_group(group_id, asgardeo_id)
            logger.info(
                f"Assigned role '{role_name}' (group: {group_name}) to user {asgardeo_id}"
            )

        except Exception as e:
            logger.error(
                f"Failed to assign role '{role_name}' to user {asgardeo_id}: {e}"
            )
            raise

    async def remove_role(self, asgardeo_id: str, role_name: str) -> None:
        """
        Remove role from user by removing from group.

        Args:
            asgardeo_id: User ID in Asgardeo
            role_name: Role name to remove

        Raises:
            Exception: If role removal fails
        """
        try:
            # Map application roles to Asgardeo groups
            # Using underscore format to match actual Asgardeo group names
            role_group_mapping = {
                "HR_Admin": "HR_Administrators",
                "HR_Manager": "HR_Managers",
                "Manager": "Team_Managers",
                "manager": "Team_Managers",
                "Employee": "Employees",
                "employee": "Employees",
            }

            group_name = role_group_mapping.get(role_name)
            if not group_name:
                logger.warning(f"No group mapping found for role: {role_name}")
                return

            # Find group by name
            group = await self.client.find_group_by_name(group_name)
            if not group:
                logger.error(f"Group not found in Asgardeo: {group_name}")
                return

            # Remove user from group
            group_id = group.get("id")
            await self.client.remove_user_from_group(group_id, asgardeo_id)
            logger.info(
                f"Removed role '{role_name}' (group: {group_name}) from user {asgardeo_id}"
            )

        except Exception as e:
            logger.error(
                f"Failed to remove role '{role_name}' from user {asgardeo_id}: {e}"
            )
            raise

    async def exchange_code_for_token(
        self, code: str, state: str
    ) -> Optional[Dict[str, Any]]:
        """
        Exchange OAuth authorization code for tokens.

        Note: This is a placeholder. The actual OAuth flow requires
        redirect_uri and PKCE parameters which should be handled by
        the authorization server integration.

        Args:
            code: Authorization code from OAuth callback
            state: State parameter for CSRF protection

        Returns:
            Token response including access_token and id_token, or None if failed

        Raises:
            NotImplementedError: OAuth code exchange needs proper implementation
        """
        logger.warning(
            "OAuth code exchange called but not fully implemented in SCIM client"
        )
        logger.info(
            "For OAuth flows, use a dedicated OAuth client library or implement using httpx"
        )
        raise NotImplementedError(
            "OAuth authorization code flow requires additional configuration. "
            "Please implement using httpx with your redirect_uri and PKCE parameters."
        )


# Global client instance
asgardeo_client = create_asgardeo_client()

# Global service instance (wraps client with business logic)
asgardeo_service = AsgardeoService(asgardeo_client)

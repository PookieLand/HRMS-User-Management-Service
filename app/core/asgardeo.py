"""
Asgardeo client initialization for User Management Service.

This module provides a singleton instance of the AsgardeoClient
configured with credentials from environment variables.
"""

from typing import Any, Dict, List, Optional

import httpx

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

    async def preload_role_group_ids(self) -> dict[str, str]:
        """Preload and cache role -> group_id mappings for configured roles.

        This attempts to resolve each role's Asgardeo group by name and caches
        the group resource in the client. If group lookup is forbidden (403)
        or group not found, it will attempt to use environment-configured
        fallback group IDs (e.g., ASGARDEO_GROUP_ID_EMPLOYEE).

        Returns:
            Mapping of role_name -> resolved group_id (for those found)
        """
        found: dict[str, str] = {}

        for role_name, group_name in settings.ASGARDEO_GROUP_MAPPING.items():
            # First check for explicit fallback environment var
            env_var_name = f"ASGARDEO_GROUP_ID_{role_name.upper()}"
            env_group_id = getattr(settings, env_var_name, None)
            if env_group_id:
                logger.info(
                    f"Using configured group ID from {env_var_name} for role {role_name}: {env_group_id[:8]}..."
                )
                # Cache in client as a minimal resource
                self.client.cache_group({"id": env_group_id, "displayName": group_name})
                found[role_name] = env_group_id
                continue

            # Try to resolve via Asgardeo API
            try:
                group = await self.client.find_group_by_name(group_name)
                if group and group.get("id"):
                    self.client.cache_group(group)
                    found[role_name] = group.get("id")
                    logger.info(
                        f"Preloaded group '{group_name}' for role {role_name}: {found[role_name][:8]}..."
                    )
                else:
                    logger.warning(
                        f"Group '{group_name}' not found in Asgardeo for role {role_name}"
                    )
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    logger.warning(
                        f"Permission denied when preloading groups (403). Cannot read groups for role {role_name}"
                    )
                    logger.info(
                        "Set environment fallback variables ASGARDEO_GROUP_ID_<ROLE> or grant 'View Groups' permission to M2M app."
                    )
                else:
                    logger.error(
                        f"Failed to preload group '{group_name}': HTTP {e.response.status_code}"
                    )

        return found

    async def get_group_id_for_role(self, role_name: str) -> str | None:
        """Return the Asgardeo group ID for a given role name, using cache and fallbacks."""
        group_name = settings.ASGARDEO_GROUP_MAPPING.get(role_name)
        if not group_name:
            logger.warning(f"No group mapping found for role: {role_name}")
            return None

        # Check client cache
        cached = self.client.get_cached_group_id(group_name)
        if cached:
            return cached

        # Try environment fallback if present
        env_var_name = f"ASGARDEO_GROUP_ID_{role_name.upper()}"
        env_group_id = getattr(settings, env_var_name, None)
        if env_group_id:
            # Cache and return
            self.client.cache_group({"id": env_group_id, "displayName": group_name})
            return env_group_id

        # Try to find via API (may raise HTTPStatusError)
        try:
            group = await self.client.find_group_by_name(group_name)
            if group and group.get("id"):
                return group.get("id")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning(
                    f"Permission denied when listing groups (403). Consider configuring {env_var_name} or granting group view permission."
                )
                return None
            raise

        logger.warning(
            f"Could not determine group ID for '{group_name}' (role {role_name})"
        )
        return None

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

    async def assign_role(
        self, asgardeo_id: str, role_name: str, display_name: str | None = None
    ) -> bool:
        """
        Assign role to user via group membership.

        Simplified implementation:
        - Resolve group id (from cache, env fallback, or API lookup)
        - Obtain M2M access token
        - Use the synchronous helper in `app.asgardeo.group` to perform the SCIM PATCH.
          The helper uses `requests` directly, so it is invoked in a thread to avoid
          blocking the event loop.

        Accepts optional `display_name` which will be used as the member 'display'
        attribute when adding the user to the group. If not provided, the user's
        primary email will be used when available, otherwise the user id is used.

        Returns:
            True if assignment succeeded, False if skipped or failed (non-blocking).
        """
        # Resolve mapped group name
        group_name = settings.ASGARDEO_GROUP_MAPPING.get(role_name)
        if not group_name:
            logger.warning(f"No group mapping found for role: {role_name}")
            return False

        # Try to determine group id (cache, env fallback, or API lookup)
        group_id = await self.get_group_id_for_role(role_name)
        if not group_id:
            logger.warning(
                f"Could not determine group ID for role '{role_name}' (group: {group_name}). Role assignment skipped."
            )
            return False

        # Determine the display value to use for the member object.
        # Prefer explicit argument, then try to fetch the user's primary email,
        # and finally fall back to the user id string.
        member_display = display_name
        if not member_display:
            try:
                user_data = await self.client.get_user(asgardeo_id)
                emails = user_data.get("emails", []) if user_data else []
                member_display = emails[0].get("value") if emails else None
            except Exception as e:
                logger.debug(f"Unable to fetch user email for {asgardeo_id}: {e}")

        if not member_display:
            member_display = str(asgardeo_id)

        # Get an access token for PATCHing the group
        try:
            access_token = await self.client.get_access_token()
        except Exception as e:
            logger.error(f"Failed to obtain M2M access token for group assignment: {e}")
            return False

        # Perform the (blocking) requests-based group assignment in a thread
        try:
            import asyncio

            from app.asgardeo.group import assign_user_to_group

            logger.info(
                f"Assigning user {asgardeo_id} (display={member_display}) to group {group_id} ({group_name})"
            )

            await asyncio.to_thread(
                assign_user_to_group,
                access_token,
                asgardeo_id,
                group_id,
                member_display,
            )

            logger.info(
                f"Assigned role '{role_name}' (group: {group_name}) to user {asgardeo_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Failed to assign role '{role_name}' to user {asgardeo_id}: {e}"
            )
            logger.warning(
                "Role assignment failed (non-blocking). User created but not assigned to group."
            )
            return False

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
                "Manager": "Managers",
                "manager": "Managers",
                "Employee": "Employees",
                "employee": "Employees",
            }

            group_name = role_group_mapping.get(role_name)
            if not group_name:
                logger.warning(f"No group mapping found for role: {role_name}")
                return

            group_id = None

            # Try to find group by name
            try:
                group = await self.client.find_group_by_name(group_name)
                if group:
                    group_id = group.get("id")
                else:
                    logger.error(f"Group not found in Asgardeo: {group_name}")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    # Permission denied - fallback to environment-configured group IDs
                    logger.warning(
                        f"Permission denied when listing groups (403). "
                        f"Attempting fallback with environment-configured group IDs."
                    )

                    # Try to get group ID from environment variables
                    env_var_name = f"ASGARDEO_GROUP_ID_{role_name.upper()}"
                    group_id = getattr(settings, env_var_name, None)

                    if not group_id:
                        logger.error(
                            f"Group lookup failed and no fallback group ID configured. "
                            f"Set environment variable {env_var_name} or grant group read permissions to M2M app."
                        )
                        return
                    else:
                        logger.info(
                            f"Using configured group ID from {env_var_name}: {group_id[:8]}..."
                        )
                else:
                    raise

            if not group_id:
                logger.warning(
                    f"Could not determine group ID for '{group_name}'. Role removal skipped."
                )
                return

            # Remove user from group
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


def get_asgardeo_service() -> AsgardeoService:
    """Return the global AsgardeoService instance"""
    return asgardeo_service

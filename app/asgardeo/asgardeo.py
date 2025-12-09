"""
Asgardeo SCIM2 Client for Python FastAPI v1.0.0
=========================================++++++
A comprehensive client for interacting with Asgardeo's SCIM2 API endpoints.

Validated against Asgardeo SCIM2 API as of November 2025.
for:
    User Management
    Group Management (for HR role-based access control)

OAuth2 Client Credentials flow for machine-to-machine authentication.
"""

import base64
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AsgardeoConfig(BaseModel):
    """Configuration for Asgardeo client"""

    organization: str = Field(..., description="Asgardeo organization name")
    client_id: str = Field(..., description="OAuth2 Client ID")
    client_secret: str = Field(..., description="OAuth2 Client Secret")
    base_url: str = Field(
        default="https://api.asgardeo.io", description="Asgardeo API base URL"
    )
    token_cache_buffer: int = Field(
        default=300, description="Token refresh buffer in seconds (5 min)"
    )


class TokenResponse(BaseModel):
    """OAuth2 Token Response"""

    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None
    issued_at: datetime = Field(default_factory=datetime.now)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        expiry_time = self.issued_at + timedelta(seconds=self.expires_in)
        return datetime.now() >= expiry_time

    @property
    def needs_refresh(self) -> bool:
        """Check if token needs refresh (with buffer)"""
        expiry_time = self.issued_at + timedelta(seconds=self.expires_in - 300)
        return datetime.now() >= expiry_time


class AsgardeoClient:
    """
    Asgardeo SCIM2 API Client with OAuth2 Client Credentials authentication

    This client provides comprehensive access to Asgardeo's SCIM2 endpoints for
    managing users, groups, and other identity resources in a machine-to-machine context.
    """

    # Required OAuth2 Scopes for SCIM2 operations
    SCOPES = {
        "users": {
            "list": "internal_user_mgt_list",
            "create": "internal_user_mgt_create",
            "view": "internal_user_mgt_view",
            "update": "internal_user_mgt_update",
            "delete": "internal_user_mgt_delete",
        },
        "groups": {
            "list": "internal_group_mgt_view",  # Asgardeo uses 'view' for listing groups
            "create": "internal_group_mgt_create",
            "view": "internal_group_mgt_view",
            "update": "internal_group_mgt_update",
            "delete": "internal_group_mgt_delete",
        },
    }

    def __init__(self, config: AsgardeoConfig):
        """
        Initialize Asgardeo client

        Args:
            config: AsgardeoConfig instance with organization, client_id, and client_secret
        """
        self.config = config
        self._token: Optional[TokenResponse] = None
        self._http_client = httpx.AsyncClient(timeout=30.0)

        # Build base URLs
        self.token_url = f"{config.base_url}/t/{config.organization}/oauth2/token"
        self.scim_base_url = f"{config.base_url}/t/{config.organization}/scim2"

        # Log initialization
        logger.info("=" * 60)
        logger.info("ASGARDEO CLIENT INITIALIZED")
        logger.info("=" * 60)
        logger.info(f"Organization: {config.organization}")
        logger.info(f"Token URL: {self.token_url}")
        logger.info(f"SCIM Base URL: {self.scim_base_url}")
        logger.info(
            f"Client ID configured: {'Yes' if config.client_id else 'NO - MISSING!'}"
        )
        logger.info(
            f"Client Secret configured: {'Yes' if config.client_secret else 'NO - MISSING!'}"
        )
        if not config.client_id or not config.client_secret:
            logger.error("WARNING: Client credentials are missing! M2M auth will fail.")
            logger.error(
                "Set ASGARDEO_CLIENT_ID and ASGARDEO_CLIENT_SECRET in environment."
            )
        logger.info("=" * 60)

    async def close(self):
        """Close the HTTP client"""
        await self._http_client.aclose()

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    # ==================== Authentication ====================

    def _get_basic_auth_header(self) -> str:
        """Generate Basic Auth header for OAuth2 token endpoint"""
        credentials = f"{self.config.client_id}:{self.config.client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    async def _fetch_access_token(self, scopes: List[str]) -> TokenResponse:
        """
        Fetch access token using OAuth2 Client Credentials flow

        Args:
            scopes: List of OAuth2 scopes to request

        Returns:
            TokenResponse with access token and metadata

        Raises:
            httpx.HTTPStatusError: If token request fails
        """
        logger.info("=" * 60)
        logger.info("M2M AUTHENTICATION: Starting OAuth2 Client Credentials flow")
        logger.info("=" * 60)
        logger.info(f"Token URL: {self.token_url}")
        logger.info(f"Organization: {self.config.organization}")
        logger.info(
            f"Client ID: {self.config.client_id[:8]}...{self.config.client_id[-4:] if len(self.config.client_id) > 12 else '****'}"
        )
        logger.info(
            f"Client Secret: {'*' * 8}...{self.config.client_secret[-4:] if len(self.config.client_secret) > 4 else '****'}"
        )
        logger.info(f"Requested scopes: {scopes}")

        headers = {
            "Authorization": self._get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {"grant_type": "client_credentials", "scope": " ".join(scopes)}

        logger.debug(
            f"Request headers (auth redacted): Content-Type={headers['Content-Type']}"
        )
        logger.debug(
            f"Request data: grant_type={data['grant_type']}, scope={data['scope']}"
        )

        try:
            response = await self._http_client.post(
                self.token_url, headers=headers, data=data
            )

            logger.info(f"M2M AUTH Response Status: {response.status_code}")

            if not response.is_success:
                logger.error("=" * 60)
                logger.error("M2M AUTHENTICATION FAILED!")
                logger.error("=" * 60)
                logger.error(f"Status Code: {response.status_code}")
                logger.error(f"Response Headers: {dict(response.headers)}")
                try:
                    error_body = response.json()
                    logger.error(f"Error Response Body: {error_body}")
                    if "error" in error_body:
                        logger.error(f"Error Type: {error_body.get('error')}")
                        logger.error(
                            f"Error Description: {error_body.get('error_description', 'No description')}"
                        )
                except Exception:
                    logger.error(f"Error Response Text: {response.text}")

                logger.error("-" * 60)
                logger.error("TROUBLESHOOTING CHECKLIST:")
                logger.error("1. Is ASGARDEO_CLIENT_ID set correctly in environment?")
                logger.error(
                    "2. Is ASGARDEO_CLIENT_SECRET set correctly in environment?"
                )
                logger.error(
                    "3. Is ASGARDEO_ORG set correctly (should be: pookieland)?"
                )
                logger.error("4. Is the M2M application created in Asgardeo Console?")
                logger.error("5. Does the M2M app have the required API permissions?")
                logger.error(
                    "   Required scopes: internal_user_mgt_create, internal_user_mgt_view,"
                )
                logger.error(
                    "   internal_user_mgt_list, internal_group_mgt_view, internal_group_mgt_update"
                )
                logger.error(
                    "6. Is the M2M application's protocol set to 'Client Credentials'?"
                )
                logger.error("-" * 60)

            response.raise_for_status()

            token_data = response.json()
            logger.info("=" * 60)
            logger.info("M2M AUTHENTICATION SUCCESSFUL!")
            logger.info("=" * 60)
            logger.info(f"Token Type: {token_data.get('token_type')}")
            logger.info(f"Expires In: {token_data.get('expires_in')} seconds")
            logger.info(f"Granted Scopes: {token_data.get('scope', 'Not returned')}")
            logger.info(
                f"Access Token: {token_data.get('access_token', '')[:20]}...{token_data.get('access_token', '')[-10:]}"
            )

            return TokenResponse(**token_data)

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP Error during M2M auth: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during M2M auth: {type(e).__name__}: {e}")
            raise

    async def get_access_token(self, scopes: Optional[List[str]] = None) -> str:
        """
        Get a valid access token, refreshing if necessary

        Args:
            scopes: Optional list of scopes. If None, requests all user and group management scopes

        Returns:
            Valid access token string
        """
        if scopes is None:
            # Default to all user and group management scopes
            scopes = list(self.SCOPES["users"].values()) + list(
                self.SCOPES["groups"].values()
            )

        # Check if we need to fetch a new token
        if self._token is None:
            logger.info("No cached token, fetching new M2M access token...")
            self._token = await self._fetch_access_token(scopes)
        elif self._token.needs_refresh:
            logger.info("Cached token needs refresh, fetching new M2M access token...")
            self._token = await self._fetch_access_token(scopes)
        else:
            logger.debug("Using cached M2M access token")

        return self._token.access_token

    async def test_m2m_connection(self) -> Dict[str, Any]:
        """
        Test the M2M connection to Asgardeo.

        This method attempts to authenticate and provides detailed diagnostics.

        Returns:
            Dictionary with connection test results
        """
        result = {
            "success": False,
            "token_url": self.token_url,
            "organization": self.config.organization,
            "client_id_preview": f"{self.config.client_id[:8]}...{self.config.client_id[-4:]}"
            if len(self.config.client_id) > 12
            else "***",
            "scim_base_url": self.scim_base_url,
            "error": None,
            "token_info": None,
            "troubleshooting": [],
        }

        try:
            logger.info("Testing M2M connection to Asgardeo...")

            # Try to get an access token
            token = await self.get_access_token()

            result["success"] = True
            result["token_info"] = {
                "token_type": self._token.token_type if self._token else None,
                "expires_in": self._token.expires_in if self._token else None,
                "scope": self._token.scope if self._token else None,
                "token_preview": f"{token[:20]}...{token[-10:]}" if token else None,
            }

            logger.info("M2M connection test PASSED!")

        except httpx.HTTPStatusError as e:
            result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            result["troubleshooting"] = [
                "Check ASGARDEO_CLIENT_ID is correct",
                "Check ASGARDEO_CLIENT_SECRET is correct",
                "Check ASGARDEO_ORG matches your Asgardeo organization",
                "Verify M2M application exists in Asgardeo Console",
                "Verify M2M application has required API permissions",
                "Ensure application protocol is 'Client Credentials'",
            ]
            logger.error(f"M2M connection test FAILED: {result['error']}")

        except Exception as e:
            result["error"] = f"{type(e).__name__}: {str(e)}"
            result["troubleshooting"] = [
                "Check network connectivity to api.asgardeo.io",
                "Verify environment variables are set",
            ]
            logger.error(f"M2M connection test FAILED: {result['error']}")

        return result

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        scopes: Optional[List[str]] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Make authenticated request to Asgardeo API

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path (e.g., "/Users")
            scopes: OAuth2 scopes required for this operation
            json: JSON request body
            params: Query parameters

        Returns:
            Response JSON as dictionary
        """
        token = await self.get_access_token(scopes)
        url = f"{self.scim_base_url}{endpoint}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
        }

        logger.debug(f"Making {method} request to {url}")
        if json:
            logger.debug(f"Request body: {json}")

        response = await self._http_client.request(
            method=method, url=url, headers=headers, json=json, params=params
        )

        # Log response details for debugging
        if not response.is_success:
            logger.error(
                f"Asgardeo API error: {method} {url} returned {response.status_code}"
            )
            try:
                error_body = response.json()
                logger.error(f"Error response body: {error_body}")
            except Exception:
                logger.error(f"Error response text: {response.text}")

        response.raise_for_status()

        # Handle empty responses (e.g., DELETE operations)
        if response.status_code == 204 or not response.content:
            return {"status": "success", "statusCode": response.status_code}

        return response.json()

    # ==================== User Management ====================

    async def list_users(
        self,
        filter: Optional[str] = None,
        start_index: int = 1,
        count: int = 50,
        attributes: Optional[List[str]] = None,
        excluded_attributes: Optional[List[str]] = None,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List users with optional filtering and pagination

        Args:
            filter: SCIM filter expression (e.g., 'userName eq "john@example.com"')
            start_index: Starting index for pagination (1-based)
            count: Number of results per page (max 100 for orgs after Nov 19, 2024)
            attributes: List of attributes to include in response
            excluded_attributes: List of attributes to exclude from response
            domain: Name of the user store where filtering needs to be applied

        Returns:
            Dictionary with users list and pagination info

        Example:
            users = await client.list_users(
                filter='emails.value eq "john@example.com"',
                count=10,
                domain="PRIMARY"
            )
        """
        params = {
            "startIndex": start_index,
            "count": min(count, 100),  # Asgardeo max is 100
        }

        if filter:
            params["filter"] = filter
        if attributes:
            params["attributes"] = ",".join(attributes)
        if excluded_attributes:
            params["excludedAttributes"] = ",".join(excluded_attributes)
        if domain:
            params["domain"] = domain

        return await self._make_request(
            "GET", "/Users", scopes=[self.SCOPES["users"]["list"]], params=params
        )

    async def search_users(
        self,
        filter: Optional[str] = None,
        attributes: Optional[List[str]] = None,
        start_index: int = 1,
        count: int = 50,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Search users using POST (supports complex queries)

        Args:
            filter: SCIM filter expression
            attributes: List of SCIM attributes to return
            start_index: Starting index for pagination
            count: Number of results per page
            domain: Name of the user store where filtering needs to be applied

        Returns:
            Dictionary with search results

        Example:
            results = await client.search_users(
                filter='userName sw ki and name.familyName co err',
                attributes=['name.familyName', 'userName'],
                domain='PRIMARY',
                count=10
            )
        """
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
            "startIndex": start_index,
            "count": min(count, 100),
        }

        if filter:
            body["filter"] = filter
        if attributes:
            body["attributes"] = attributes
        if domain:
            body["domain"] = domain

        return await self._make_request(
            "POST", "/Users/.search", scopes=[self.SCOPES["users"]["list"]], json=body
        )

    async def get_user(self, user_id: str) -> Dict[str, Any]:
        """
        Get user by ID

        Args:
            user_id: Unique user identifier

        Returns:
            User resource dictionary
        """
        return await self._make_request(
            "GET", f"/Users/{user_id}", scopes=[self.SCOPES["users"]["view"]]
        )

    async def create_user(
        self,
        username: str,
        password: Optional[str] = None,
        email: Optional[str] = None,
        given_name: Optional[str] = None,
        family_name: Optional[str] = None,
        ask_password: bool = False,
        verify_email: bool = False,
        additional_attributes: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Create a new user

        Args:
            username: Username (format: DEFAULT/<email> or alphanumeric based on org config)
            password: User password (required unless ask_password=True)
            email: User email address
            given_name: User's first name
            family_name: User's last name
            ask_password: If True, user receives invitation to set their own password
            verify_email: If True, user receives email verification request (when password is set)
            additional_attributes: Additional SCIM attributes

        Returns:
            Created user resource

        Example:
            # Invite user to set password
            user = await client.create_user(
                username="DEFAULT/john.doe@example.com",
                email="john.doe@example.com",
                given_name="John",
                family_name="Doe",
                ask_password=True
            )

            # Set password with email verification
            user = await client.create_user(
                username="DEFAULT/jane@example.com",
                password="SecurePass123!",
                email="jane@example.com",
                given_name="Jane",
                family_name="Doe",
                verify_email=True
            )
        """
        body = {"schemas": [], "userName": username}

        # Name object
        if given_name or family_name:
            body["name"] = {}
            if given_name:
                body["name"]["givenName"] = given_name
            if family_name:
                body["name"]["familyName"] = family_name

        # Email
        if email:
            body["emails"] = [{"primary": True, "value": email}]

        # Password or invitation
        if ask_password:
            body["urn:scim:wso2:schema"] = {"askPassword": True}
        elif password:
            body["password"] = password
            # Add email verification if requested
            if verify_email:
                body["urn:scim:wso2:schema"] = {"verifyEmail": True}
        else:
            raise ValueError(
                "Either password must be provided or ask_password must be True"
            )

        # Merge additional attributes
        if additional_attributes:
            body.update(additional_attributes)

        return await self._make_request(
            "POST", "/Users", scopes=[self.SCOPES["users"]["create"]], json=body
        )

    async def update_user(
        self, user_id: str, user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update user (full replacement with PUT)

        Args:
            user_id: User ID to update
            user_data: Complete user resource data

        Returns:
            Updated user resource

        Note:
            The schemas field should be an empty array [] as per Asgardeo API spec
        """
        if "schemas" not in user_data:
            user_data["schemas"] = []

        return await self._make_request(
            "PUT",
            f"/Users/{user_id}",
            scopes=[self.SCOPES["users"]["update"]],
            json=user_data,
        )

    async def patch_user(
        self, user_id: str, operations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Partially update user with PATCH operations

        Args:
            user_id: User ID to update
            operations: List of PATCH operations (add, replace, remove)

        Returns:
            Updated user resource

        Example:
            await client.patch_user(
                user_id="123",
                operations=[
                    {
                        "op": "replace",
                        "path": "emails[type eq \"work\"].value",
                        "value": "newemail@example.com"
                    },
                    {
                        "op": "add",
                        "value": {
                            "phoneNumbers": [{"type": "work", "value": "+1234567890"}]
                        }
                    }
                ]
            )
        """
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        }

        return await self._make_request(
            "PATCH",
            f"/Users/{user_id}",
            scopes=[self.SCOPES["users"]["update"]],
            json=body,
        )

    async def delete_user(self, user_id: str) -> Dict[str, Any]:
        """
        Delete user

        Args:
            user_id: User ID to delete

        Returns:
            Success status dictionary
        """
        return await self._make_request(
            "DELETE", f"/Users/{user_id}", scopes=[self.SCOPES["users"]["delete"]]
        )

    # ==================== Group Management (RBAC for HR System) ====================

    async def list_groups(
        self, filter: Optional[str] = None, start_index: int = 1, count: int = 50
    ) -> Dict[str, Any]:
        """
        List groups with optional filtering

        Note: For HR system, primarily used to find role-based groups by name

        Args:
            filter: SCIM filter expression (e.g., 'displayName eq "HR-Admins"')
            start_index: Starting index for pagination
            count: Number of results per page

        Returns:
            Dictionary with groups list and pagination info

        Example:
            # Find group by name
            groups = await client.list_groups(
                filter='displayName eq "HR-Managers"'
            )
            if groups['totalResults'] > 0:
                group_id = groups['Resources'][0]['id']
        """
        params = {"startIndex": start_index, "count": min(count, 100)}

        if filter:
            params["filter"] = filter

        return await self._make_request(
            "GET", "/Groups", scopes=[self.SCOPES["groups"]["list"]], params=params
        )

    async def get_group(self, group_id: str) -> Dict[str, Any]:
        """
        Get group by ID

        Args:
            group_id: Unique group identifier

        Returns:
            Group resource dictionary with members list
        """
        return await self._make_request(
            "GET", f"/Groups/{group_id}", scopes=[self.SCOPES["groups"]["view"]]
        )

    async def create_group(
        self, display_name: str, members: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new group (typically for role-based access control)

        Note: For HR system, create groups like "HR-Admins", "HR-Managers", "Employees"

        Args:
            display_name: Group display name (e.g., "HR-Admins")
            members: Optional list of user IDs to add as initial members

        Returns:
            Created group resource

        Example:
            # Create role groups during system setup
            admin_group = await client.create_group("HR-Admins")
            manager_group = await client.create_group("HR-Managers")
            employee_group = await client.create_group("Employees")
        """
        body = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": display_name,
        }

        if members:
            body["members"] = [{"value": user_id} for user_id in members]

        return await self._make_request(
            "POST", "/Groups", scopes=[self.SCOPES["groups"]["create"]], json=body
        )

    async def add_user_to_group(
        self, group_id: str, user_id: str, display_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add a user to a group using SCIM 2.0 PATCH operation.

        Uses the recommended Asgardeo SCIM 2.0 Groups API format with
        explicit "path": "members" in the PATCH operation.

        Args:
            group_id: Group ID (UUID) to add user to
            user_id: User ID (SCIM UUID from Asgardeo) to add
            display_name: Optional user display name

        Returns:
            Updated group resource

        Example:
            # Assign user to HR Manager role
            await client.add_user_to_group(
                group_id=manager_group_id,
                user_id=new_user_id,
                display_name="John Doe"
            )
        """
        logger.info(f"Adding user {user_id} to group {group_id}")

        member = {"value": user_id}
        if display_name:
            member["display"] = display_name

        # SCIM 2.0 PATCH format for Asgardeo
        # See: https://wso2.com/asgardeo/docs/apis/scim2-groups-rest-api/
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members", "value": [member]}],
        }

        try:
            result = await self._make_request(
                "PATCH",
                f"/Groups/{group_id}",
                scopes=[self.SCOPES["groups"]["update"]],
                json=body,
            )
            logger.info(f"Successfully added user {user_id} to group {group_id}")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to add user {user_id} to group {group_id}: "
                f"HTTP {e.response.status_code}"
            )
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error adding user {user_id} to group {group_id}: {e}"
            )
            raise

    async def remove_user_from_group(
        self, group_id: str, user_id: str
    ) -> Dict[str, Any]:
        """
        Remove a user from a group (simplified helper for HR role changes)

        Args:
            group_id: Group ID to remove user from
            user_id: User ID to remove

        Returns:
            Updated group resource

        Example:
            # Remove user from old role when changing roles
            await client.remove_user_from_group(
                group_id=old_role_group_id,
                user_id=user_id
            )
        """
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}],
        }

        return await self._make_request(
            "PATCH",
            f"/Groups/{group_id}",
            scopes=[self.SCOPES["groups"]["update"]],
            json=body,
        )

    # ==================== Bulk Operations ====================

    async def bulk_operations(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute bulk operations (create, update, delete multiple resources)

        Args:
            operations: List of bulk operation objects

        Returns:
            Bulk operation results

        Example:
            result = await client.bulk_operations([
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "user1",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "user1@example.com",
                        "password": "Password123!"
                    }
                },
                {
                    "method": "PATCH",
                    "path": "/Users/existing-user-id",
                    "bulkId": "user2",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "path": "active", "value": False}]
                    }
                }
            ])
        """
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": operations,
        }

        # Bulk operations require multiple scopes
        scopes = list(self.SCOPES["users"].values()) + list(
            self.SCOPES["groups"].values()
        )

        return await self._make_request("POST", "/Bulk", scopes=scopes, json=body)

    # ==================== Resource Type & Schema Discovery ====================

    async def get_resource_types(self) -> Dict[str, Any]:
        """
        Get available SCIM resource types

        Returns:
            List of available resource types (User, Group, etc.)
        """
        return await self._make_request("GET", "/ResourceTypes", scopes=[])

    async def get_schemas(self) -> Dict[str, Any]:
        """
        Get SCIM schemas

        Returns:
            Available SCIM schemas
        """
        return await self._make_request("GET", "/Schemas", scopes=[])

    async def get_service_provider_config(self) -> Dict[str, Any]:
        """
        Get service provider configuration

        Returns:
            Service provider capabilities and configuration
        """
        return await self._make_request("GET", "/ServiceProviderConfig", scopes=[])

    # ==================== Helper Methods ====================

    async def find_group_by_name(self, group_name: str) -> Optional[Dict[str, Any]]:
        """
        Find a group by its display name (helper for HR role management)

        Args:
            group_name: Group display name to search for

        Returns:
            Group resource if found, None otherwise

        Example:
            # Find HR Managers group
            group = await client.find_group_by_name("HR-Managers")
            if group:
                group_id = group['id']
        """
        groups = await self.list_groups(filter=f'displayName eq "{group_name}"')

        if groups.get("totalResults", 0) > 0:
            return groups["Resources"][0]
        return None

    async def assign_user_role(
        self,
        user_id: str,
        role_group_name: str,
        user_display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Assign a user to a role group (high-level helper for HR system)

        This method finds the role group by name and adds the user to it.
        If the group doesn't exist, it will be created.

        Args:
            user_id: User ID to assign role to
            role_group_name: Role group name (e.g., "HR-Admins", "HR-Managers", "Employees")
            user_display_name: Optional user display name

        Returns:
            Updated group resource

        Example:
            # Assign user to HR Manager role
            await client.assign_user_role(
                user_id=new_user_id,
                role_group_name="HR-Managers",
                user_display_name="John Doe"
            )
        """
        # Find or create group
        group = await self.find_group_by_name(role_group_name)

        if not group:
            # Create the role group if it doesn't exist
            group = await self.create_group(role_group_name)

        # Add user to group
        return await self.add_user_to_group(
            group_id=group["id"], user_id=user_id, display_name=user_display_name
        )

    def build_filter(self, field: str, operator: str, value: str) -> str:
        """
        Build SCIM filter string

        Args:
            field: Attribute name (e.g., 'userName', 'emails.value')
            operator: SCIM operator ('eq', 'ne', 'co', 'sw', 'ew', 'pr')
            value: Value to compare

        Returns:
            SCIM filter string

        Note:
            Asgardeo supports: 'eq', 'ne', 'co', 'sw', 'ew', and 'and' operators

        Example:
            filter = client.build_filter('userName', 'eq', 'john@example.com')
            # Returns: 'userName eq "john@example.com"'
        """
        if operator.lower() == "pr":
            return f"{field} pr"
        return f'{field} {operator} "{value}"'

    def combine_filters(self, filters: List[str], operator: str = "and") -> str:
        """
        Combine multiple SCIM filters

        Args:
            filters: List of filter strings
            operator: Logical operator ('and', 'or')

        Returns:
            Combined filter string

        Example:
            filter = client.combine_filters([
                client.build_filter('userName', 'co', '@example.com'),
                client.build_filter('active', 'eq', 'true')
            ], 'and')
        """
        return f" {operator} ".join([f"({f})" for f in filters])

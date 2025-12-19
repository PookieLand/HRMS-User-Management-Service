import base64
from typing import Optional

import requests
from loguru import logger

from app.core.config import settings


# access token request
def get_m2m_access_token():
    """
    Request M2M access token from Asgardeo OAuth2 endpoint.

    This function makes a POST request to the Asgardeo token endpoint with
    client credentials grant type and comprehensive logging.

    Returns:
        str: The access token response as a string
    """
    # Use configured Asgardeo organization from settings
    ORG_NAME = settings.ASGARDEO_ORG

    # Token endpoint URL derived from settings
    token_url = settings.token_url

    # Prefer explicit AUTH_HEADER if present (can be either 'Basic <b64>' or raw base64).
    # Otherwise, build Basic auth header from client credentials (client_id:client_secret)
    auth_header = settings.AUTH_HEADER
    if auth_header:
        # If the env value includes the 'Basic ' prefix, strip it so we always add 'Basic ' later.
        if auth_header.startswith("Basic "):
            auth_header = auth_header[len("Basic ") :]
    else:
        if not settings.ASGARDEO_CLIENT_ID or not settings.ASGARDEO_CLIENT_SECRET:
            raise ValueError(
                "ASGARDEO_CLIENT_ID and ASGARDEO_CLIENT_SECRET must be configured in environment"
            )
        credentials = (
            f"{settings.ASGARDEO_CLIENT_ID}:{settings.ASGARDEO_CLIENT_SECRET}".encode()
        )
        auth_header = base64.b64encode(credentials).decode()

    # Define the grant type and required scopes
    grant_type = "client_credentials"
    scopes = [
        "internal_user_mgt_create",
        "internal_user_mgt_list",
        "internal_user_mgt_view",
        "internal_user_mgt_delete",
        "internal_user_mgt_update",
        "internal_group_mgt_delete",
        "internal_group_mgt_create",
        "internal_group_mgt_update",
        "internal_group_mgt_view",
    ]

    # Prepare request headers
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {auth_header}",
    }

    # Prepare request data
    scope_string = " ".join(scopes)
    data = {"grant_type": grant_type, "scope": scope_string}

    logger.info("Initiating M2M access token request")
    logger.debug(f"Token URL: {token_url}")
    logger.debug(f"Grant Type: {grant_type}")
    logger.debug(f"Requested Scopes: {scopes}")
    logger.debug(
        "Headers: Content-Type=application/x-www-form-urlencoded, Authorization=Basic [REDACTED]"
    )

    try:
        logger.info("Sending POST request to Asgardeo token endpoint")
        response = requests.post(token_url, headers=headers, data=data)

        logger.debug(f"Response Status Code: {response.status_code}")
        # logger.debug(f"Response Headers: {dict(response.headers)}")

        response.raise_for_status()

        logger.info("M2M access token request successful")

        return dict(response.json()).get("access_token")

    except requests.exceptions.RequestException as e:
        logger.error(f"M2M access token request failed: {str(e)}")
        logger.error(
            f"Response Status: {e.response.status_code if e.response else 'No response'}"
        )
        raise


# Assign a user to a Group
# This is a working and correct implementation with all the schemas and everything
def assign_user_to_group(
    access_token: str, user_id: str, group_id: str, display_name: Optional[str] = None
) -> dict:
    """
    Assign a user to a group in Asgardeo using SCIM2 PATCH API.

    Args:
        access_token (str): Bearer token for authentication
        user_id (str): The UUID of the user to add to the group
        group_id (str): The UUID of the group
        display_name (Optional[str]): Optional display name (usually email) to attach to group member

    Returns:
        dict: The updated group response from Asgardeo
    """
    if not access_token:
        raise ValueError("access_token is required to assign user to group")
    if not user_id:
        raise ValueError("user_id is required to assign user to group")
    if not group_id:
        raise ValueError("group_id is required to assign user to group")

    org_name = settings.ASGARDEO_ORG

    # Construct the SCIM2 Groups PATCH endpoint URL
    group_url = f"https://api.asgardeo.io/t/{org_name}/scim2/Groups/{group_id}"

    logger.info(f"Initiating user assignment to group: {group_id}")
    logger.debug(f"Group PATCH endpoint URL: {group_url}")
    logger.debug(f"User ID to assign: {user_id}")
    logger.debug(f"Display name: {display_name}")

    try:
        # Prepare request headers
        headers = {
            "accept": "application/scim+json",
            "Content-Type": "application/scim+json",
            "Authorization": f"Bearer {access_token}",
        }

        logger.debug("Headers prepared for user-to-group assignment request")

        # Construct the PATCH payload (SCIM PatchOp)
        member_display = display_name if display_name else str(user_id)
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "add",
                    "value": {
                        "members": [
                            {
                                "display": member_display,
                                "value": user_id,
                            }
                        ]
                    },
                }
            ],
        }

        logger.debug(f"PATCH payload prepared: {payload}")

        # Send PATCH request to assign user to group
        logger.info("Sending PATCH request to assign user to group")
        response = requests.patch(group_url, headers=headers, json=payload)

        logger.debug(f"Response Status Code: {response.status_code}")

        # Log response body for debugging (especially useful for errors)
        if response.status_code >= 400:
            logger.error(f"Error response body: {response.text}")
            try:
                error_json = response.json()
                logger.error(f"Error response JSON: {error_json}")
            except Exception:
                pass

        response.raise_for_status()

        logger.info("User-to-group assignment successful")

        return response.json()

    except requests.exceptions.RequestException as e:
        logger.error(f"User-to-group assignment failed: {str(e)}")
        logger.error(
            f"Response Status: {e.response.status_code if e.response else 'No response'}"
        )
        if e.response is not None:
            logger.error(f"Response body: {e.response.text}")
            try:
                error_json = e.response.json()
                logger.error(f"Response JSON: {error_json}")
            except Exception:
                pass
        raise


def assign_user_to_group_with_env_token(
    user_id: str, group_id: str, display_name: Optional[str] = None
) -> dict:
    """
    Convenience wrapper: obtain M2M access token from settings and assign a user to a group.

    NOTE: This function performs network IO using requests and is synchronous.
    If called from async code, run it in a thread (e.g., asyncio.to_thread).
    """
    logger.info(
        "Fetching M2M access token from Asgardeo (using configured client credentials)"
    )
    access_token = get_m2m_access_token()
    return assign_user_to_group(access_token, user_id, group_id, display_name)

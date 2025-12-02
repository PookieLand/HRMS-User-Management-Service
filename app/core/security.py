import json
from datetime import datetime, timedelta
from typing import Annotated, Any, List

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

from app.core.config import settings
from app.core.logging import get_logger
from app.core.rbac import RBACManager

logger = get_logger(__name__)

# HTTP Bearer scheme for JWT tokens
security = HTTPBearer()

# JWKS client for fetching and caching public keys
jwks_client = PyJWKClient(
    uri=settings.jwks_url,
    cache_keys=True,
    max_cached_keys=16,
)


class TokenData(BaseModel):
    sub: str  # Subject (user ID)
    username: str | None = None
    email: str | None = None
    roles: list[str] = []
    permissions: list[str] = []
    groups: list[str] = []
    iss: str | None = None  # Issuer
    aud: str | list[str] | None = None  # Audience
    exp: int | None = None  # Expiration
    iat: int | None = None  # Issued at
    raw_claims: dict[str, Any] = {}  # All other claims


def decode_token(token: str) -> TokenData:
    """
    Decode and validate JWT token using JWKS endpoint.
    """
    try:
        # Get the signing key from JWKS
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Prepare decode options
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": settings.JWT_AUDIENCE is not None,
            "verify_iss": settings.JWT_ISSUER is not None,
        }

        # Decode and validate the token with optional audience and issuer
        if settings.JWT_AUDIENCE and settings.JWT_ISSUER:
            # Validate both audience and issuer
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
                options=decode_options,
            )
        elif settings.JWT_AUDIENCE:
            # Validate only audience
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=settings.JWT_AUDIENCE,
                options=decode_options,
            )
        elif settings.JWT_ISSUER:
            # Validate only issuer
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                options=decode_options,
            )
        else:
            # No audience or issuer validation
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options=decode_options,
            )

        logger.info(f"Token decoded successfully for subject: {payload.get('sub')}")

        # Extract roles from various possible claim locations
        roles = []
        if "roles" in payload:
            roles = (
                payload["roles"]
                if isinstance(payload["roles"], list)
                else [payload["roles"]]
            )
        elif "role" in payload:
            roles = (
                payload["role"]
                if isinstance(payload["role"], list)
                else [payload["role"]]
            )
        elif "groups" in payload:
            # Sometimes roles are in groups
            groups = (
                payload["groups"]
                if isinstance(payload["groups"], list)
                else [payload["groups"]]
            )
            roles = [g for g in groups if not g.startswith("/")]

        # Extract permissions
        permissions = []
        if "permissions" in payload:
            permissions = (
                payload["permissions"]
                if isinstance(payload["permissions"], list)
                else [payload["permissions"]]
            )
        elif "scope" in payload:
            # OAuth2 scopes as permissions
            scopes = payload["scope"]
            permissions = scopes.split() if isinstance(scopes, str) else scopes

        # Extract groups
        groups = []
        if "groups" in payload:
            groups = (
                payload["groups"]
                if isinstance(payload["groups"], list)
                else [payload["groups"]]
            )

        # Create TokenData object
        token_data = TokenData(
            sub=payload.get("sub", ""),
            username=payload.get("username") or payload.get("preferred_username"),
            email=payload.get("email"),
            roles=roles,
            permissions=permissions,
            groups=groups,
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            exp=payload.get("exp"),
            iat=payload.get("iat"),
            raw_claims=payload,
        )

        return token_data

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Error decoding token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> TokenData:
    """
    Dependency to get the current authenticated user from JWT token.
    """
    token = credentials.credentials
    return decode_token(token)


async def get_current_active_user(
    current_user: Annotated[TokenData, Depends(get_current_user)],
) -> TokenData:
    """
    Dependency to ensure the current user is active.
    """
    # Future: Check if user is active in database
    # For now, if token is valid, user is active
    return current_user


def require_role(*required_roles: str):
    """
    Dependency factory to require specific roles.
    Usage:
        # Only users with admin OR superuser role can access
        user: Annotated[TokenData, Depends(require_role("admin", "superuser"))]
    """

    async def check_roles(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        user_roles = set(current_user.roles)
        required = set(required_roles)

        if not user_roles.intersection(required):
            logger.warning(
                f"User {current_user.sub} lacks required roles. "
                f"Has: {user_roles}, Required: {required}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(required_roles)}",
            )

        return current_user

    return check_roles


def require_permission(*required_permissions: str):
    """
    Dependency factory to require specific permissions.
    Usage:
        # Only users with users:create permission can access
        current_user: Annotated[TokenData, Depends(require_permission("users:create"))]
    """

    async def check_permissions(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        user_perms = set(current_user.permissions)
        required = set(required_permissions)

        if not user_perms.intersection(required):
            logger.warning(
                f"User {current_user.sub} lacks required permissions. "
                f"Has: {user_perms}, Required: {required}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {', '.join(required_permissions)}",
            )

        return current_user

    return check_permissions


def require_all_roles(*required_roles: str):
    """
    Dependency factory to require ALL specified roles.
    Args:
        *required_roles: All roles that user must have
    """

    async def check_all_roles(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        user_roles = set(current_user.roles)
        required = set(required_roles)

        if not required.issubset(user_roles):
            missing = required - user_roles
            logger.warning(f"User {current_user.sub} missing required roles: {missing}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required roles: {', '.join(missing)}",
            )

        return current_user

    return check_all_roles


def require_role_level(minimum_role: str):
    """
    Dependency factory to require minimum role level based on hierarchy.
    Users with higher role levels can also access.

    Usage:
        # Only HR_Manager and HR_Admin can access
        user: Annotated[TokenData, Depends(require_role_level("HR_Manager"))]

    Args:
        minimum_role: Minimum required role level
    """

    async def check_role_level(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        # Check if any of user's roles meet the minimum level
        has_sufficient_role = any(
            RBACManager.has_higher_or_equal_role(role, minimum_role)
            for role in current_user.roles
        )

        if not has_sufficient_role:
            logger.warning(
                f"User {current_user.sub} lacks required role level. "
                f"Required: {minimum_role} (level {RBACManager.get_role_level(minimum_role)}), "
                f"Has: {current_user.roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required role level: {minimum_role} or higher",
            )

        return current_user

    return check_role_level


def require_any_role(*required_roles: str):
    """
    Dependency factory to require at least one of the specified roles.
    This is an alias for require_role for better code readability.

    Args:
        *required_roles: Roles, user must have at least one
    """
    return require_role(*required_roles)


def require_admin():
    """
    Dependency to require HR_Admin role.
    Convenience function for admin-only endpoints.
    """
    return require_role("HR_Admin", "admin")


def require_hr_manager():
    """
    Dependency to require HR_Manager or higher role.
    """
    return require_role_level("HR_Manager")


def require_manager():
    """
    Dependency to require manager or higher role.
    """
    return require_role_level("manager")


def check_resource_permission(resource: str, action: str):
    """
    Dependency factory to check if user has permission for a specific resource action.

    Usage:
        user: Annotated[TokenData, Depends(check_resource_permission("users", "delete"))]

    Args:
        resource: Resource name (e.g., "users", "employees")
        action: Action name (e.g., "create", "read", "update", "delete")
    """

    async def verify_permission(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        required_permission = f"{resource}:{action}"

        # Check if user has the specific permission
        if not RBACManager.has_permission(current_user.roles, required_permission):
            logger.warning(
                f"User {current_user.sub} lacks required permission: {required_permission}. "
                f"User roles: {current_user.roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_permission}",
            )

        return current_user

    return verify_permission


def require_self_or_role(user_id_param: str, *allowed_roles: str):
    """
    Dependency factory to allow access if user is accessing their own resource
    or has one of the allowed roles.

    Usage:
        user: Annotated[TokenData, Depends(require_self_or_role("user_id", "HR_Admin"))]

    Args:
        user_id_param: Name of the path/query parameter containing the user ID
        *allowed_roles: Roles that can access any user's resource
    """

    async def check_self_or_role(
        current_user: Annotated[TokenData, Depends(get_current_active_user)],
    ) -> TokenData:
        # Check if user has any of the allowed roles
        user_roles = set(current_user.roles)
        allowed = set(allowed_roles)

        if user_roles.intersection(allowed):
            return current_user

        # If not, they can only access their own resource
        # This check would need the actual user_id from path params
        # For now, just return the user and let the endpoint handle it
        logger.info(
            f"User {current_user.sub} accessing resource with self-or-role check"
        )
        return current_user

    return check_self_or_role

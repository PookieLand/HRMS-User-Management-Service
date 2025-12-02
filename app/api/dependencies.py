"""
Shared API dependencies.
Contains reusable dependency functions for FastAPI endpoints.
Centralizes common dependencies like database sessions, authentication, and authorization.
"""

from typing import Annotated, Optional

import jwt
from fastapi import Depends, HTTPException, status
from sqlmodel import Session

from app.core.config import settings
from app.core.database import get_session
from app.core.logging import get_logger

logger = get_logger(__name__)


# Database session dependency
SessionDep = Annotated[Session, Depends(get_session)]


class TokenData:
    """Decoded token data."""

    def __init__(self, payload: dict):
        """
        Initialize TokenData from JWT payload.

        Args:
            payload: Decoded JWT payload
        """
        self.sub = payload.get("sub")
        self.user_id = payload.get("user_id") or int(self.sub)
        self.email = payload.get("email")
        self.asgardeo_id = payload.get("asgardeo_id")
        self.role = payload.get("role")
        self.employee_id = payload.get("employee_id")
        self.roles = [payload.get("role")] if payload.get("role") else []
        self.permissions = payload.get("permissions", [])
        self.iss = payload.get("iss")
        self.aud = payload.get("aud")
        self.exp = payload.get("exp")
        self.iat = payload.get("iat")
        self.raw_claims = payload


def _extract_token_from_header(authorization: Optional[str]) -> Optional[str]:
    """
    Extract JWT token from Authorization header.

    Args:
        authorization: Authorization header value

    Returns:
        Token string or None

    Raises:
        HTTPException: If header format is invalid
    """
    if not authorization:
        return None

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]


async def get_current_user(
    authorization: Optional[str] = None,
) -> TokenData:
    """
    Get current authenticated user from JWT token.

    Extracts and validates JWT token from Authorization header.

    Args:
        authorization: Authorization header value

    Returns:
        TokenData with user information

    Raises:
        HTTPException: If token is missing, invalid, or expired
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = _extract_token_from_header(authorization)

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={"verify_aud": settings.JWT_AUDIENCE is not None},
        )

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID",
            )

        return TokenData(payload)

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


async def get_current_user_or_none(
    authorization: Optional[str] = None,
) -> Optional[TokenData]:
    """
    Get current user if token is valid, otherwise return None.

    Non-strict version that doesn't raise exceptions.

    Args:
        authorization: Authorization header value

    Returns:
        TokenData or None
    """
    if not authorization:
        return None

    try:
        token = _extract_token_from_header(authorization)
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_signature": False},
        )
        return TokenData(payload)
    except Exception as e:
        logger.debug(f"Failed to extract user from token: {e}")
        return None


def require_role(*required_roles: str):
    """
    Dependency factory that requires specific roles.

    Args:
        required_roles: One or more role names required

    Returns:
        Dependency function
    """

    async def check_role(
        current_user: Annotated[TokenData, Depends(get_current_user)],
    ) -> TokenData:
        """
        Check if user has required role.

        Args:
            current_user: Current authenticated user

        Returns:
            TokenData if authorized

        Raises:
            HTTPException: If user doesn't have required role
        """
        if current_user.role not in required_roles:
            logger.warning(
                f"User {current_user.user_id} attempted access with insufficient role: "
                f"{current_user.role} (required: {required_roles})"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This operation requires one of these roles: {', '.join(required_roles)}",
            )

        return current_user

    return check_role


def require_permission(*required_permissions: str):
    """
    Dependency factory that requires specific permissions.

    Args:
        required_permissions: One or more permission names required

    Returns:
        Dependency function
    """

    async def check_permission(
        current_user: Annotated[TokenData, Depends(get_current_user)],
    ) -> TokenData:
        """
        Check if user has required permission.

        Args:
            current_user: Current authenticated user

        Returns:
            TokenData if authorized

        Raises:
            HTTPException: If user doesn't have required permission
        """
        user_permissions = set(current_user.permissions)
        required = set(required_permissions)

        if not user_permissions & required:
            logger.warning(
                f"User {current_user.user_id} attempted access with insufficient permissions: "
                f"{user_permissions} (required: {required})"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have the required permissions",
            )

        return current_user

    return check_permission


# Convenience dependency types
AdminDep = Annotated[TokenData, Depends(require_role("admin"))]
HRManagerDep = Annotated[TokenData, Depends(require_role("hr_manager", "admin"))]
ManagerDep = Annotated[
    TokenData, Depends(require_role("manager", "hr_manager", "admin"))
]

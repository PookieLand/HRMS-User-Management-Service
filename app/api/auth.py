"""
Authentication API endpoints for User Management Service.

Provides endpoints for:
- User signup (direct registration)
- Profile management
- Password change
- Token verification
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select

from app.core.asgardeo import asgardeo_service
from app.core.cache import cache_user_profile, invalidate_user_cache
from app.core.config import settings
from app.core.database import get_session
from app.core.events import (
    EventType,
    UserCreatedEvent,
    UserUpdatedEvent,
    create_event,
)
from app.core.integrations import (
    audit_client,
    employee_client,
    notification_client,
)
from app.core.kafka import publish_event
from app.core.logging import get_logger
from app.core.security import (
    TokenData,
    get_current_active_user,
    get_current_user,
)
from app.core.topics import KafkaTopics
from app.models.users import (
    MessageResponse,
    SignupResponse,
    User,
    UserProfileResponse,
    UserUpdate,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


class SignupRequest(BaseModel):
    """Request body for user signup."""

    email: EmailStr
    password: str
    first_name: str
    last_name: str
    phone: str


class ChangePasswordRequest(BaseModel):
    """Request body for password change."""

    old_password: str
    new_password: str


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password against strength requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        return (
            False,
            f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters",
        )

    if settings.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if settings.REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if settings.REQUIRE_SPECIAL_CHARS and not any(
        c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password
    ):
        return False, "Password must contain at least one special character"

    return True, ""


@router.post(
    "/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED
)
async def signup(
    request: SignupRequest,
    session: Annotated[Session, Depends(get_session)],
):
    """
    Sign up a new user (direct registration).

    Note: This endpoint is for direct user signup. For HR-initiated
    onboarding, use the /api/v1/onboarding endpoints.

    Process:
    1. Validate password strength
    2. Check email uniqueness
    3. Create user in Asgardeo via SCIM2
    4. Assign default employee role
    5. Create local user record
    6. Create employee record
    7. Publish events and send notifications

    Args:
        request: Signup request with email, password, name, phone
        session: Database session

    Returns:
        SignupResponse with user_id and status
    """
    logger.info(f"Signup request for email: {request.email}")

    # Validate password strength
    is_valid, error_msg = validate_password_strength(request.password)
    if not is_valid:
        logger.warning(f"Weak password for signup: {request.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # Check if email already exists
    existing_user = session.exec(
        select(User).where(User.email == request.email)
    ).first()
    if existing_user:
        logger.warning(f"Email already exists: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )

    # Create user in Asgardeo
    try:
        asgardeo_data = await asgardeo_service.create_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
        )
        asgardeo_id = asgardeo_data["asgardeo_id"]
        logger.info(f"User created in Asgardeo: {asgardeo_id}")
    except Exception as e:
        logger.error(f"Failed to create user in Asgardeo: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user in identity provider",
        )

    # Assign default employee role
    try:
        await asgardeo_service.assign_role(asgardeo_id, "Employee")
        logger.info(f"Assigned default role (Employee) to user: {asgardeo_id}")
    except Exception as e:
        logger.warning(f"Failed to assign default role: {e}")

    # Create local user record
    try:
        db_user = User(
            asgardeo_id=asgardeo_id,
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
            role="employee",
            status="active",
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        logger.info(f"User created locally: {db_user.id}")

        # Publish user created event
        try:
            event_data = UserCreatedEvent(
                user_id=db_user.id,
                email=db_user.email,
                first_name=db_user.first_name or "",
                last_name=db_user.last_name or "",
                role=db_user.role,
                status=db_user.status,
                asgardeo_id=asgardeo_id,
            )
            event = create_event(EventType.USER_CREATED, event_data)
            await publish_event(KafkaTopics.USER_CREATED, event)
            logger.info(f"Published user created event for: {db_user.id}")
        except Exception as e:
            logger.warning(f"Failed to publish user created event: {e}")

    except Exception as e:
        logger.error(f"Failed to create user locally: {e}")
        # Try to clean up Asgardeo user
        try:
            await asgardeo_service.delete_user(asgardeo_id)
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user record",
        )

    # Create employee record
    try:
        employee_data = await employee_client.create_employee(
            user_id=db_user.id,
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
        )
        if employee_data:
            db_user.employee_id = employee_data.get("id")
            session.add(db_user)
            session.commit()
            session.refresh(db_user)
            logger.info(f"Employee created: {db_user.employee_id}")
    except Exception as e:
        logger.warning(f"Failed to create employee record: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=db_user.id,
            action="signup",
            resource_type="user",
            resource_id=db_user.id,
            description=f"User signed up: {request.email}",
        )
    except Exception as e:
        logger.warning(f"Failed to log signup audit: {e}")

    # Send welcome email
    try:
        await notification_client.send_account_created_notification(
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
        )
    except Exception as e:
        logger.warning(f"Failed to send welcome email: {e}")

    logger.info(f"Signup completed for: {request.email}")

    return SignupResponse(
        user_id=db_user.id,
        email=db_user.email,
        asgardeo_id=asgardeo_id,
        status="created",
    )


@router.get("/users/me", response_model=UserProfileResponse)
async def get_profile(
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_session)],
):
    """
    Get current user's profile.

    Validates the Asgardeo JWT token and returns the user's profile
    from the local database.

    Returns:
        User profile information
    """
    asgardeo_id = current_user.sub

    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Update last login
    user.last_login = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)

    logger.info(f"Profile accessed by user: {user.id}")

    profile = UserProfileResponse(
        id=user.id,
        asgardeo_id=user.asgardeo_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone,
        role=user.role,
        employee_id=user.employee_id,
        status=user.status,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
    )

    # Cache the profile
    await cache_user_profile(user.id, profile.model_dump(mode="json"))

    return profile


@router.put("/users/me", response_model=UserProfileResponse)
async def update_profile(
    update_data: UserUpdate,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_session)],
):
    """
    Update current user's profile.

    Args:
        update_data: Fields to update
        current_user: Token data from validated Asgardeo JWT
        session: Database session

    Returns:
        Updated user profile
    """
    asgardeo_id = current_user.sub

    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Update fields
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if value is not None and hasattr(user, key):
            setattr(user, key, value)

    user.updated_at = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)

    # Publish user updated event
    try:
        event_data = UserUpdatedEvent(
            user_id=user.id,
            email=user.email,
            updated_fields=update_dict,
        )
        event = create_event(
            EventType.USER_UPDATED,
            event_data,
            actor_user_id=str(user.id),
        )
        await publish_event(KafkaTopics.USER_UPDATED, event)
        logger.info(f"Published user updated event for: {user.id}")
    except Exception as e:
        logger.warning(f"Failed to publish user updated event: {e}")

    # Sync to Asgardeo
    try:
        await asgardeo_service.update_user(
            asgardeo_id=user.asgardeo_id,
            first_name=update_data.first_name,
            last_name=update_data.last_name,
            phone=update_data.phone,
        )
        logger.info(f"Profile synced to Asgardeo: {user.asgardeo_id}")
    except Exception as e:
        logger.warning(f"Failed to sync profile to Asgardeo: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=user.id,
            action="update_profile",
            resource_type="user",
            resource_id=user.id,
            description="User profile updated",
        )
    except Exception as e:
        logger.warning(f"Failed to log profile update: {e}")

    # Invalidate cache
    await invalidate_user_cache(user.id)

    logger.info(f"Profile updated for user: {user.id}")

    return UserProfileResponse(
        id=user.id,
        asgardeo_id=user.asgardeo_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone,
        role=user.role,
        employee_id=user.employee_id,
        status=user.status,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
    )


@router.put("/users/me/change-password", response_model=MessageResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_session)],
):
    """
    Change current user's password.

    Updates the password in Asgardeo via SCIM2 API.

    Args:
        request: Old and new passwords
        current_user: Token data from validated Asgardeo JWT
        session: Database session

    Returns:
        Success message
    """
    asgardeo_id = current_user.sub

    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Validate new password
    is_valid, error_msg = validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # Update password in Asgardeo
    try:
        await asgardeo_service.update_user(
            asgardeo_id=user.asgardeo_id,
            updates={"password": request.new_password},
        )
        logger.info(f"Password changed for user: {user.id}")
    except Exception as e:
        logger.error(f"Failed to change password in Asgardeo: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password",
        )

    # Send notification
    try:
        await notification_client.send_password_changed_notification(
            email=user.email,
            first_name=user.first_name or "User",
        )
    except Exception as e:
        logger.warning(f"Failed to send password change notification: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=user.id,
            action="change_password",
            resource_type="user",
            resource_id=user.id,
            description="User changed password",
        )
    except Exception as e:
        logger.warning(f"Failed to log password change: {e}")

    return MessageResponse(message="Password changed successfully")


@router.get("/verify")
async def verify_token(
    current_user: Annotated[TokenData, Depends(get_current_user)],
) -> dict:
    """
    Verify that provided Asgardeo JWT token is valid.

    Uses JWKS validation to verify the token signature.

    Returns:
        Token validity status and user information
    """
    return {
        "valid": True,
        "asgardeo_id": current_user.sub,
        "email": current_user.email,
        "groups": current_user.groups,
        "roles": current_user.roles,
        "message": "Token is valid",
    }


@router.get("/whoami")
async def whoami(
    current_user: Annotated[TokenData, Depends(get_current_user)],
) -> dict:
    """
    Get current user information from Asgardeo JWT token claims.

    Returns:
        User identification, roles, and groups from token
    """
    return {
        "asgardeo_id": current_user.sub,
        "email": current_user.email,
        "username": current_user.username,
        "groups": current_user.groups,
        "roles": current_user.roles,
        "permissions": current_user.permissions,
        "issuer": current_user.iss,
    }


@router.get("/debug-token")
async def debug_token(
    current_user: Annotated[TokenData, Depends(get_current_user)],
) -> dict:
    """
    Debug endpoint to inspect JWT token claims.

    This endpoint is useful for troubleshooting authentication and
    role assignment issues. It shows both the raw claims from the
    token and the processed/mapped values.

    WARNING: This endpoint should be disabled or protected in production.

    Returns:
        Detailed token information including raw claims
    """
    return {
        "processed": {
            "asgardeo_id": current_user.sub,
            "email": current_user.email,
            "username": current_user.username,
            "roles": current_user.roles,
            "groups": current_user.groups,
            "permissions": current_user.permissions,
            "issuer": current_user.iss,
            "audience": current_user.aud,
            "expires_at": current_user.exp,
            "issued_at": current_user.iat,
        },
        "raw_claims": current_user.raw_claims,
        "notes": {
            "role_mapping": "Groups like 'HR_Administrators' are mapped to 'HR_Admin'",
            "expected_groups": {
                "HR_Administrators": "HR_Admin",
                "HR_Managers": "HR_Manager",
                "Team_Managers": "manager",
                "Employees": "employee",
            },
        },
    }


@router.post("/logout", response_model=MessageResponse)
async def logout(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Logout endpoint.

    In SPA architecture, logout is primarily client-side:
    - Frontend clears the token
    - Frontend uses Asgardeo SDK signOut()
    - Backend logs the event for audit

    Returns:
        Success message
    """
    logger.info(f"User logout: {current_user.sub}")

    return MessageResponse(message="Logged out successfully")

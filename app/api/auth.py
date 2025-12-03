from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select

from app.core.asgardeo import asgardeo_service
from app.core.config import settings
from app.core.database import get_session
from app.core.integrations import (
    audit_client,
    employee_client,
    notification_client,
)
from app.core.logging import get_logger
from app.core.security import (
    TokenData,
    get_current_active_user,
    get_current_user,
)
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


# Request/Response Models
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


# Helper Functions
def _validate_password_strength(password: str) -> tuple[bool, str]:
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


# Routes
@router.post(
    "/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED
)
async def signup(
    request: SignupRequest,
    session: Annotated[Session, Depends(get_session)],
):
    """
    Sign up a new user.

    This endpoint uses M2M (Machine-to-Machine) authentication to create
    users in Asgardeo via SCIM2 API.

    Process:
    1. Validate input and password strength
    2. Check email uniqueness
    3. Create user in Asgardeo via SCIM2 (M2M)
    4. Assign to default employee group
    5. Create local user record
    6. Create employee record
    7. Send welcome notification

    Args:
        request: Signup request with email, password, name, phone
        session: Database session

    Returns:
        SignupResponse with user_id and status

    Raises:
        HTTPException: For various validation/creation errors
    """
    logger.info(f"Signup request for email: {request.email}")

    # Validate password strength
    is_valid, error_msg = _validate_password_strength(request.password)
    if not is_valid:
        logger.warning(f"Weak password for signup: {request.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # Check if email already exists in local database
    existing_user = session.exec(
        select(User).where(User.email == request.email)
    ).first()
    if existing_user:
        logger.warning(f"Email already exists: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )

    # Create user in Asgardeo via SCIM2 (using M2M credentials)
    try:
        asgardeo_data = await asgardeo_service.create_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
        )
        asgardeo_id = asgardeo_data["asgardeo_id"]
        logger.info(f"User created in Asgardeo via SCIM2: {asgardeo_id}")
    except Exception as e:
        logger.error(f"Failed to create user in Asgardeo: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user in identity provider",
        )

    # Assign user to default employee group (role)
    try:
        await asgardeo_service.assign_role(asgardeo_id, "Employee")
        logger.info(f"✅ Assigned default role (Employee) to user: {asgardeo_id}")
    except Exception as e:
        error_str = str(e)
        if "403" in error_str or "Forbidden" in error_str:
            logger.error(
                f"❌ 403 FORBIDDEN - M2M app lacks SCIM2 Groups API permissions!\n\n"
                f"Error: {e}\n\n"
                f"🔧 REQUIRED FIX (You have authorized scopes but Groups API itself is missing):\n"
                f"1. Go to Asgardeo Console: https://console.asgardeo.io/\n"
                f"2. Navigate to: Applications → Your M2M Application\n"
                f"3. Click 'API Authorization' tab\n"
                f"4. Click 'Authorize an API Resource' button\n"
                f"5. In dropdown, select 'SCIM2 Groups API' (NOT just scopes!)\n"
                f"6. Check ALL these scopes:\n"
                f"   ✅ internal_group_mgt_view (REQUIRED for listing/searching)\n"
                f"   ✅ internal_group_mgt_update (REQUIRED for adding users)\n"
                f"   ✅ internal_group_mgt_create (optional)\n"
                f"   ✅ internal_group_mgt_delete (optional)\n"
                f"7. Click 'Finish'\n"
                f"8. Verify authorization shows 'SCIM2 Groups API' in the list\n"
                f"9. Also ensure 'Employees' group exists:\n"
                f"   User Management → Groups → Create 'Employees' group if missing\n"
                f"10. Run: scripts/test-m2m-permissions.sh to verify\n\n"
                f"⚠️  User created in Asgardeo but NOT assigned to default role.\n"
                f"   User will be able to login but may lack proper permissions."
            )
        else:
            logger.error(
                f"❌ FAILED to assign default role 'Employee' to user {asgardeo_id}\n"
                f"Error: {e}\n\n"
                f"This may be a network issue or the 'Employees' group doesn't exist.\n"
                f"Check logs above for more details."
            )

    # Create local user record
    try:
        db_user = User(
            asgardeo_id=asgardeo_id,
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
            role="employee",  # Default role
            status="active",
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        logger.info(f"User created locally: {db_user.id}")
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

    # Create employee record in employee service
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
            logger.info(f"✅ Employee created successfully: {db_user.employee_id}")
    except Exception as e:
        logger.warning(f"Failed to create employee record (non-blocking): {e}")

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

    logger.info(f"Signup completed successfully for: {request.email}")

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

    This endpoint validates the Asgardeo JWT token (from frontend SPA login)
    using JWKS public key verification.

    Args:
        current_user: Token data from validated Asgardeo JWT
        session: Database session

    Returns:
        User profile information

    Raises:
        HTTPException: 404 if user not found in local database
    """
    # Extract asgardeo_id from token
    asgardeo_id = current_user.sub

    # Look up user by asgardeo_id
    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found in database: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Update last login timestamp
    user.last_login = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)

    logger.info(f"Profile accessed by user: {user.id}")

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
        last_login=user.last_login,
    )


@router.put("/users/me", response_model=UserProfileResponse)
async def update_profile(
    update_data: UserUpdate,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_session)],
):
    """
    Update current user's profile.

    This endpoint validates the Asgardeo JWT token and allows users
    to update their profile information.

    Args:
        update_data: Fields to update
        current_user: Token data from validated Asgardeo JWT
        session: Database session

    Returns:
        Updated user profile

    Raises:
        HTTPException: 404 if user not found
    """
    # Extract asgardeo_id from token
    asgardeo_id = current_user.sub

    # Look up user by asgardeo_id
    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Update local database
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if value is not None and hasattr(user, key):
            setattr(user, key, value)

    user.updated_at = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)

    # Sync to Asgardeo via SCIM2
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

    Raises:
        HTTPException: 400 if password weak/invalid, 404 if user not found
    """
    # Extract asgardeo_id from token
    asgardeo_id = current_user.sub

    # Look up user
    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found: {asgardeo_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Validate new password strength
    is_valid, error_msg = _validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # Update password in Asgardeo via SCIM2
    try:
        await asgardeo_service.update_user(
            asgardeo_id=user.asgardeo_id,
            updates={"password": request.new_password},
        )
        logger.info(f"Password changed in Asgardeo for user: {user.id}")
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

    This uses JWKS validation to verify the token signature.

    Args:
        current_user: Token data from validated Asgardeo JWT

    Returns:
        Token validity status and user information
    """
    return {
        "valid": True,
        "asgardeo_id": current_user.sub,
        "email": current_user.email,
        "groups": current_user.groups,
        "message": "Token is valid",
    }


@router.get("/whoami")
async def whoami(
    current_user: Annotated[TokenData, Depends(get_current_user)],
) -> dict:
    """
    Get current user information from Asgardeo JWT token claims.

    Args:
        current_user: Token data from validated Asgardeo JWT

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


@router.post("/logout", response_model=MessageResponse)
async def logout(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Logout endpoint.

    In this SPA architecture, logout is primarily client-side:
    - Frontend clears the token from sessionStorage
    - Frontend uses Asgardeo SDK signOut() method
    - Backend can log the event for audit purposes

    Args:
        current_user: Token data from validated Asgardeo JWT

    Returns:
        Success message
    """
    logger.info(f"User logout: {current_user.sub}")

    # Log audit event (optional)
    try:
        # Look up user ID from asgardeo_id if needed for audit
        # For now, just log with asgardeo_id
        logger.info(f"Logout event for Asgardeo user: {current_user.sub}")
    except Exception as e:
        logger.warning(f"Failed to log logout event: {e}")

    return MessageResponse(message="Logged out successfully")
